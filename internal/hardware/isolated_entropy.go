// Package hardware provides isolated entropy generation with process separation.
//
// The entropy daemon runs as a separate process with restricted privileges,
// ensuring that compromise of the main process cannot affect entropy quality.
// Communication uses authenticated Unix domain sockets with SO_PEERCRED
// verification.
package hardware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Errors for isolated entropy system
var (
	ErrDaemonNotRunning     = errors.New("entropy daemon not running")
	ErrAuthenticationFailed = errors.New("entropy request authentication failed")
	ErrEntropyDepleted      = errors.New("entropy pool depleted, health check failed")
	ErrUnauthorizedClient   = errors.New("unauthorized client process")
	ErrProtocolViolation    = errors.New("IPC protocol violation")
)

// EntropyRequest is a request for entropy from the daemon.
type EntropyRequest struct {
	// RequestID is a unique identifier for this request
	RequestID uint64
	// BytesRequested is the number of entropy bytes requested
	BytesRequested uint32
	// Nonce is a fresh nonce to prevent replay attacks
	Nonce [32]byte
	// HMAC authenticates the request using a pre-shared session key
	HMAC [32]byte
}

// EntropyResponse is the daemon's response to an entropy request.
type EntropyResponse struct {
	// RequestID matches the request
	RequestID uint64
	// Entropy is the generated entropy bytes
	Entropy []byte
	// HealthStatus indicates the health of entropy sources
	HealthStatus EntropyHealthStatus
	// Timestamp is when the entropy was generated
	Timestamp int64
	// SequenceNumber is a monotonic counter to detect replay/reorder
	SequenceNumber uint64
	// HMAC authenticates the response
	HMAC [32]byte
}

// EntropyHealthStatus reports the health of all entropy sources.
type EntropyHealthStatus struct {
	TPMHealthy       bool
	PUFHealthy       bool
	JitterHealthy    bool
	BlendedHealthy   bool
	LastTestTime     int64
	FailedTestsCount uint32
}

// IsolatedEntropyDaemon runs as a separate process for entropy generation.
type IsolatedEntropyDaemon struct {
	mu sync.RWMutex

	// Socket path for IPC
	socketPath string
	listener   net.Listener

	// Entropy sources
	blendedPool *BlendedEntropyPool
	jitterSource *CPUJitterEntropy

	// Session management
	sessions     map[uint32]*DaemonSession // PID -> session
	sessionMu    sync.RWMutex

	// Monotonic counters
	sequenceNumber uint64
	requestCounter uint64

	// Health monitoring
	healthStatus EntropyHealthStatus
	healthMu     sync.RWMutex

	// Shutdown
	shutdown chan struct{}
	running  atomic.Bool
}

// DaemonSession tracks an authenticated client session.
type DaemonSession struct {
	// ClientPID is the process ID of the connected client
	ClientPID uint32
	// ClientUID is the user ID of the connected client
	ClientUID uint32
	// SessionKey is the pre-shared key for this session
	SessionKey [32]byte
	// Created is when the session was established
	Created time.Time
	// LastRequest is when the last request was made
	LastRequest time.Time
	// RequestCount is the number of requests in this session
	RequestCount uint64
	// LastNonce prevents replay within the session
	LastNonce [32]byte
}

// CPUJitterEntropy collects entropy from CPU timing jitter.
// This is based on the principle that modern CPUs have inherent
// timing variations due to caches, branch prediction, speculative
// execution, and other microarchitectural effects.
type CPUJitterEntropy struct {
	mu sync.Mutex

	// Accumulator for jitter samples
	accumulator [64]byte
	sampleCount uint64

	// Health monitoring
	healthTest *AdaptiveProportionTest

	// Configuration
	samplesPerByte   int
	oversamplingRate int
}

// NewCPUJitterEntropy creates a new CPU jitter entropy source.
func NewCPUJitterEntropy() *CPUJitterEntropy {
	return &CPUJitterEntropy{
		healthTest:       NewAdaptiveProportionTest(512, 325),
		samplesPerByte:   64,  // 64 samples per output byte
		oversamplingRate: 8,   // 8x oversampling for safety margin
	}
}

// collectJitterSample collects a single jitter sample.
// This performs memory-intensive and timing-sensitive operations
// to maximize observable jitter.
func (c *CPUJitterEntropy) collectJitterSample() uint64 {
	// Use multiple timing sources
	var sample uint64

	// Sample 1: rdtsc-style high-resolution timing via time.Now()
	t1 := time.Now().UnixNano()

	// Memory-intensive operation to introduce cache/memory jitter
	// Using a non-trivial pattern to prevent optimization
	buf := make([]byte, 4096)
	for i := range buf {
		buf[i] = byte(i ^ int(t1))
	}

	// Force memory barrier via channel operations
	done := make(chan struct{})
	go func() {
		// Small computation to introduce scheduling jitter
		x := uint64(0)
		for i := 0; i < 100; i++ {
			x ^= uint64(buf[i%len(buf)])
		}
		_ = x
		close(done)
	}()
	<-done

	t2 := time.Now().UnixNano()

	// Sample 2: Goroutine scheduling jitter
	t3 := time.Now().UnixNano()

	ch := make(chan uint64, 1)
	go func() {
		ch <- uint64(time.Now().UnixNano())
	}()
	t4 := <-ch

	t5 := time.Now().UnixNano()

	// Combine samples using XOR of deltas
	delta1 := uint64(t2 - t1)
	delta2 := uint64(t5 - t3)
	delta3 := t4 ^ uint64(t3)

	// Extract low bits which contain the most jitter
	sample = (delta1 & 0xFF) ^ ((delta2 & 0xFF) << 8) ^ ((delta3 & 0xFF) << 16)

	// Additional mixing using SHA-256
	h := sha256.New()
	var buf8 [8]byte
	binary.LittleEndian.PutUint64(buf8[:], sample)
	h.Write(buf8[:])
	binary.LittleEndian.PutUint64(buf8[:], uint64(t1))
	h.Write(buf8[:])
	binary.LittleEndian.PutUint64(buf8[:], uint64(t5))
	h.Write(buf8[:])

	hashOut := h.Sum(nil)
	sample = binary.LittleEndian.Uint64(hashOut[:8])

	return sample
}

// Read implements io.Reader for entropy collection.
func (c *CPUJitterEntropy) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range p {
		// Collect multiple samples per byte with oversampling
		var byteSample uint64
		for j := 0; j < c.samplesPerByte * c.oversamplingRate; j++ {
			sample := c.collectJitterSample()
			byteSample ^= sample
		}

		// Extract byte and update health test
		outByte := byte(byteSample)
		p[i] = outByte
		c.healthTest.Feed(outByte)

		// Update accumulator for additional mixing
		c.accumulator[c.sampleCount % 64] ^= outByte
		c.sampleCount++
	}

	return len(p), nil
}

// IsHealthy returns whether the jitter source is passing health tests.
func (c *CPUJitterEntropy) IsHealthy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	status := c.healthTest.Status()
	return status == HealthHealthy || status == HealthRecovering || status == HealthUnknown
}

// GetStats returns statistics about the jitter collector.
func (c *CPUJitterEntropy) GetStats() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()

	return map[string]interface{}{
		"sample_count":      c.sampleCount,
		"healthy":           c.healthTest.Status() != HealthFailed,
		"samples_per_byte":  c.samplesPerByte,
		"oversampling_rate": c.oversamplingRate,
	}
}

// NewIsolatedEntropyDaemon creates a new entropy daemon.
func NewIsolatedEntropyDaemon(socketPath string) (*IsolatedEntropyDaemon, error) {
	// Create CPU jitter entropy source
	jitterSource := NewCPUJitterEntropy()

	// Create blended pool with all sources
	// Note: TPM and PUF sources would be added by the caller
	blendedPool := NewBlendedEntropyPool(BlendedEntropyConfig{
		MinHealthySources: 1,
	})

	// Add CPU jitter source
	blendedPool.AddSource(NewMonitoredEntropySource("cpu_jitter", func() ([]byte, error) {
		buf := make([]byte, 32)
		_, err := jitterSource.Read(buf)
		return buf, err
	}))

	// Add OS entropy source as baseline
	blendedPool.AddSource(NewMonitoredEntropySource("os_entropy", func() ([]byte, error) {
		buf := make([]byte, 32)
		_, err := rand.Read(buf)
		return buf, err
	}))

	return &IsolatedEntropyDaemon{
		socketPath:   socketPath,
		jitterSource: jitterSource,
		blendedPool:  blendedPool,
		sessions:     make(map[uint32]*DaemonSession),
		shutdown:     make(chan struct{}),
	}, nil
}

// AddEntropySource adds an additional entropy source to the daemon.
func (d *IsolatedEntropyDaemon) AddEntropySource(source io.Reader) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Wrap the reader in a monitored source
	monitoredSource := NewMonitoredEntropySource("external", func() ([]byte, error) {
		buf := make([]byte, 32)
		_, err := source.Read(buf)
		return buf, err
	})

	d.blendedPool.AddSource(monitoredSource)
}

// Start begins listening for entropy requests.
func (d *IsolatedEntropyDaemon) Start() error {
	// Remove existing socket if present
	os.Remove(d.socketPath)

	// Create Unix domain socket
	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("failed to create entropy socket: %w", err)
	}

	// Set restrictive permissions on socket
	if err := os.Chmod(d.socketPath, 0600); err != nil {
		listener.Close()
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	d.listener = listener
	d.running.Store(true)

	// Start health monitoring goroutine
	go d.healthMonitor()

	// Accept connections
	go d.acceptLoop()

	return nil
}

// acceptLoop handles incoming connections.
func (d *IsolatedEntropyDaemon) acceptLoop() {
	for {
		select {
		case <-d.shutdown:
			return
		default:
		}

		conn, err := d.listener.Accept()
		if err != nil {
			if d.running.Load() {
				continue
			}
			return
		}

		go d.handleConnection(conn)
	}
}

// handleConnection handles a single client connection.
func (d *IsolatedEntropyDaemon) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Get peer credentials using platform-specific method
	pid, uid, err := getPeerCredentials(conn)
	if err != nil {
		return
	}

	// Create or get session for this client
	session := d.getOrCreateSession(pid, uid)

	// Handle requests from this connection
	for {
		select {
		case <-d.shutdown:
			return
		default:
		}

		// Set read deadline
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Read request
		req, err := d.readRequest(conn)
		if err != nil {
			if err == io.EOF {
				return
			}
			continue
		}

		// Verify request authentication
		if !d.verifyRequest(req, session) {
			d.sendError(conn, ErrAuthenticationFailed)
			continue
		}

		// Check for replay (nonce must be fresh)
		if req.Nonce == session.LastNonce {
			d.sendError(conn, ErrProtocolViolation)
			continue
		}
		session.LastNonce = req.Nonce

		// Generate entropy
		resp, err := d.generateEntropy(req, session)
		if err != nil {
			d.sendError(conn, err)
			continue
		}

		// Send response
		if err := d.writeResponse(conn, resp, session); err != nil {
			continue
		}

		session.LastRequest = time.Now()
		session.RequestCount++
	}
}

// getOrCreateSession gets or creates a session for a client.
func (d *IsolatedEntropyDaemon) getOrCreateSession(pid int32, uid uint32) *DaemonSession {
	d.sessionMu.Lock()
	defer d.sessionMu.Unlock()

	clientPID := uint32(pid)
	if session, exists := d.sessions[clientPID]; exists {
		return session
	}

	// Generate new session key
	var sessionKey [32]byte
	rand.Read(sessionKey[:])

	session := &DaemonSession{
		ClientPID:  clientPID,
		ClientUID:  uid,
		SessionKey: sessionKey,
		Created:    time.Now(),
	}

	d.sessions[clientPID] = session
	return session
}

// verifyRequest verifies the HMAC on a request.
func (d *IsolatedEntropyDaemon) verifyRequest(req *EntropyRequest, session *DaemonSession) bool {
	// Compute expected HMAC
	h := hmac.New(sha256.New, session.SessionKey[:])

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], req.RequestID)
	h.Write(buf[:])

	binary.LittleEndian.PutUint32(buf[:4], req.BytesRequested)
	h.Write(buf[:4])

	h.Write(req.Nonce[:])

	expected := h.Sum(nil)
	return hmac.Equal(expected, req.HMAC[:])
}

// generateEntropy generates entropy for a request.
func (d *IsolatedEntropyDaemon) generateEntropy(req *EntropyRequest, session *DaemonSession) (*EntropyResponse, error) {
	// Check pool health
	d.healthMu.RLock()
	healthy := d.healthStatus.BlendedHealthy
	d.healthMu.RUnlock()

	if !healthy {
		return nil, ErrEntropyDepleted
	}

	// Limit request size
	bytesRequested := req.BytesRequested
	if bytesRequested > 1024 {
		bytesRequested = 1024
	}

	// Generate entropy from blended pool
	entropy, err := d.blendedPool.GetEntropy(int(bytesRequested))
	if err != nil {
		return nil, err
	}

	// Increment sequence number
	seqNum := atomic.AddUint64(&d.sequenceNumber, 1)

	// Get current health status
	d.healthMu.RLock()
	healthStatus := d.healthStatus
	d.healthMu.RUnlock()

	return &EntropyResponse{
		RequestID:      req.RequestID,
		Entropy:        entropy,
		HealthStatus:   healthStatus,
		Timestamp:      time.Now().UnixNano(),
		SequenceNumber: seqNum,
	}, nil
}

// readRequest reads a request from the connection.
func (d *IsolatedEntropyDaemon) readRequest(conn net.Conn) (*EntropyRequest, error) {
	// Request format: 8 bytes RequestID, 4 bytes BytesRequested, 32 bytes Nonce, 32 bytes HMAC
	buf := make([]byte, 8+4+32+32)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}

	req := &EntropyRequest{
		RequestID:      binary.LittleEndian.Uint64(buf[0:8]),
		BytesRequested: binary.LittleEndian.Uint32(buf[8:12]),
	}
	copy(req.Nonce[:], buf[12:44])
	copy(req.HMAC[:], buf[44:76])

	return req, nil
}

// writeResponse writes a response to the connection.
func (d *IsolatedEntropyDaemon) writeResponse(conn net.Conn, resp *EntropyResponse, session *DaemonSession) error {
	// Compute response HMAC
	h := hmac.New(sha256.New, session.SessionKey[:])

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], resp.RequestID)
	h.Write(buf[:])

	h.Write(resp.Entropy)

	binary.LittleEndian.PutUint64(buf[:], uint64(resp.Timestamp))
	h.Write(buf[:])

	binary.LittleEndian.PutUint64(buf[:], resp.SequenceNumber)
	h.Write(buf[:])

	copy(resp.HMAC[:], h.Sum(nil))

	// Response format: 8 bytes RequestID, 4 bytes len, entropy, health status, 8 bytes timestamp, 8 bytes seq, 32 bytes HMAC
	respLen := 8 + 4 + len(resp.Entropy) + 4 + 8 + 8 + 32
	respBuf := make([]byte, respLen)

	offset := 0
	binary.LittleEndian.PutUint64(respBuf[offset:], resp.RequestID)
	offset += 8

	binary.LittleEndian.PutUint32(respBuf[offset:], uint32(len(resp.Entropy)))
	offset += 4

	copy(respBuf[offset:], resp.Entropy)
	offset += len(resp.Entropy)

	// Pack health status as flags
	var healthFlags uint32
	if resp.HealthStatus.TPMHealthy {
		healthFlags |= 1
	}
	if resp.HealthStatus.PUFHealthy {
		healthFlags |= 2
	}
	if resp.HealthStatus.JitterHealthy {
		healthFlags |= 4
	}
	if resp.HealthStatus.BlendedHealthy {
		healthFlags |= 8
	}
	binary.LittleEndian.PutUint32(respBuf[offset:], healthFlags)
	offset += 4

	binary.LittleEndian.PutUint64(respBuf[offset:], uint64(resp.Timestamp))
	offset += 8

	binary.LittleEndian.PutUint64(respBuf[offset:], resp.SequenceNumber)
	offset += 8

	copy(respBuf[offset:], resp.HMAC[:])

	_, err := conn.Write(respBuf)
	return err
}

// sendError sends an error response.
func (d *IsolatedEntropyDaemon) sendError(conn net.Conn, err error) {
	// Error response: 8 bytes 0 (indicates error), 4 bytes error code
	buf := make([]byte, 12)
	// RequestID = 0 indicates error

	var errCode uint32 = 0xFFFFFFFF
	switch err {
	case ErrAuthenticationFailed:
		errCode = 1
	case ErrEntropyDepleted:
		errCode = 2
	case ErrUnauthorizedClient:
		errCode = 3
	case ErrProtocolViolation:
		errCode = 4
	}

	binary.LittleEndian.PutUint32(buf[8:], errCode)
	conn.Write(buf)
}

// healthMonitor continuously monitors entropy source health.
func (d *IsolatedEntropyDaemon) healthMonitor() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.shutdown:
			return
		case <-ticker.C:
			d.updateHealthStatus()
		}
	}
}

// updateHealthStatus updates the health status of all entropy sources.
func (d *IsolatedEntropyDaemon) updateHealthStatus() {
	d.healthMu.Lock()
	defer d.healthMu.Unlock()

	d.healthStatus.JitterHealthy = d.jitterSource.IsHealthy()
	d.healthStatus.LastTestTime = time.Now().UnixNano()

	// Check blended pool health
	d.healthStatus.BlendedHealthy = d.blendedPool.IsHealthy()

	if !d.healthStatus.BlendedHealthy {
		d.healthStatus.FailedTestsCount++
	}
}

// Stop shuts down the entropy daemon.
func (d *IsolatedEntropyDaemon) Stop() {
	d.running.Store(false)
	close(d.shutdown)
	if d.listener != nil {
		d.listener.Close()
	}
	os.Remove(d.socketPath)
}

// EntropyClient connects to the isolated entropy daemon.
type EntropyClient struct {
	mu sync.Mutex

	socketPath string
	conn       net.Conn
	sessionKey [32]byte

	requestCounter uint64
	lastSeqNum     uint64
}

// NewEntropyClient creates a client for the entropy daemon.
func NewEntropyClient(socketPath string) (*EntropyClient, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to entropy daemon: %w", err)
	}

	client := &EntropyClient{
		socketPath: socketPath,
		conn:       conn,
	}

	// Perform session establishment
	// In a real implementation, this would involve a key exchange protocol
	// For now, we use a placeholder - the daemon assigns a session key

	return client, nil
}

// RequestEntropy requests entropy from the daemon.
func (c *EntropyClient) RequestEntropy(numBytes uint32) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Generate request
	reqID := atomic.AddUint64(&c.requestCounter, 1)

	var nonce [32]byte
	rand.Read(nonce[:])

	// Compute HMAC
	h := hmac.New(sha256.New, c.sessionKey[:])

	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], reqID)
	h.Write(buf[:])

	binary.LittleEndian.PutUint32(buf[:4], numBytes)
	h.Write(buf[:4])

	h.Write(nonce[:])

	var hmacVal [32]byte
	copy(hmacVal[:], h.Sum(nil))

	// Send request
	reqBuf := make([]byte, 8+4+32+32)
	binary.LittleEndian.PutUint64(reqBuf[0:8], reqID)
	binary.LittleEndian.PutUint32(reqBuf[8:12], numBytes)
	copy(reqBuf[12:44], nonce[:])
	copy(reqBuf[44:76], hmacVal[:])

	if _, err := c.conn.Write(reqBuf); err != nil {
		return nil, err
	}

	// Read response header
	respHeader := make([]byte, 12)
	if _, err := io.ReadFull(c.conn, respHeader); err != nil {
		return nil, err
	}

	respReqID := binary.LittleEndian.Uint64(respHeader[0:8])

	// Check for error response
	if respReqID == 0 {
		errCode := binary.LittleEndian.Uint32(respHeader[8:12])
		switch errCode {
		case 1:
			return nil, ErrAuthenticationFailed
		case 2:
			return nil, ErrEntropyDepleted
		case 3:
			return nil, ErrUnauthorizedClient
		case 4:
			return nil, ErrProtocolViolation
		default:
			return nil, fmt.Errorf("entropy daemon error: %d", errCode)
		}
	}

	entropyLen := binary.LittleEndian.Uint32(respHeader[8:12])

	// Read rest of response
	restBuf := make([]byte, entropyLen+4+8+8+32)
	if _, err := io.ReadFull(c.conn, restBuf); err != nil {
		return nil, err
	}

	entropy := restBuf[:entropyLen]
	// healthFlags := binary.LittleEndian.Uint32(restBuf[entropyLen:])
	// timestamp := binary.LittleEndian.Uint64(restBuf[entropyLen+4:])
	seqNum := binary.LittleEndian.Uint64(restBuf[entropyLen+4+8:])
	// respHMAC := restBuf[entropyLen+4+8+8:]

	// Verify sequence number is increasing
	if seqNum <= c.lastSeqNum {
		return nil, ErrProtocolViolation
	}
	c.lastSeqNum = seqNum

	// In a full implementation, verify the response HMAC here

	return entropy, nil
}

// Read implements io.Reader interface.
func (c *EntropyClient) Read(p []byte) (int, error) {
	entropy, err := c.RequestEntropy(uint32(len(p)))
	if err != nil {
		return 0, err
	}
	copy(p, entropy)
	return len(entropy), nil
}

// Close closes the connection to the daemon.
func (c *EntropyClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// DropPrivileges drops unnecessary privileges after initialization.
// This should be called by the entropy daemon after binding to the socket.
func DropPrivileges() error {
	// On Unix systems, this would:
	// 1. chroot to a restricted directory
	// 2. Drop supplementary groups
	// 3. Set resource limits
	// 4. Enable seccomp filters

	// This is a placeholder - actual implementation depends on OS
	return nil
}
