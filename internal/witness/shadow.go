package witness

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ShadowStrategy determines how file content is stored in the shadow cache.
type ShadowStrategy uint8

const (
	// ShadowFull stores the complete file content (< 256 KB).
	ShadowFull ShadowStrategy = 0
	// ShadowChunked stores content-defined chunk references (256 KB - 10 MB).
	ShadowChunked ShadowStrategy = 1
	// ShadowSize stores only the file size (> 10 MB).
	ShadowSize ShadowStrategy = 2
)

const (
	// FullThreshold is the maximum size for storing full content (256 KB).
	FullThreshold = 256 * 1024
	// ChunkedThreshold is the maximum size for chunked storage (10 MB).
	ChunkedThreshold = 10 * 1024 * 1024

	// Chunk size parameters for content-defined chunking.
	chunkTargetSize = 4 * 1024  // ~4KB average
	chunkMinSize    = 1 * 1024  // 1KB minimum
	chunkMaxSize    = 16 * 1024 // 16KB maximum

	// Rolling hash mask for boundary detection (gives ~4KB average).
	chunkMask = 0xFFF

	// Shadow file version.
	shadowVersion = 1

	// AES-GCM nonce size.
	nonceSize = 12
)

var (
	// ErrCorruptedShadow indicates the shadow file is corrupted.
	ErrCorruptedShadow = errors.New("corrupted shadow file")
	// ErrDecryptionFailed indicates decryption of shadow file failed.
	ErrDecryptionFailed = errors.New("shadow decryption failed")
	// ErrInvalidVersion indicates an unsupported shadow file version.
	ErrInvalidVersion = errors.New("invalid shadow file version")
)

// ShadowFile represents a cached shadow of a file's content.
type ShadowFile struct {
	Version     uint8
	ContentHash [32]byte
	FileSize    int64
	TimestampNs int64
	Strategy    ShadowStrategy
	Content     []byte     // Used when Strategy == ShadowFull
	Chunks      []ChunkRef // Used when Strategy == ShadowChunked
}

// ChunkRef represents a reference to a content-defined chunk.
type ChunkRef struct {
	Offset int64
	Length int64
	Hash   [32]byte
}

// ShadowCache manages persistent encrypted shadow storage.
type ShadowCache struct {
	baseDir    string
	encryptKey [32]byte
	mu         sync.RWMutex
}

// NewShadowCache creates a shadow cache with encryption key derived from signing key.
// The encryption key is derived as sha256(signingKey || "shadow-cache").
func NewShadowCache(baseDir string, signingKey []byte) (*ShadowCache, error) {
	// Derive encryption key from signing key
	h := sha256.New()
	h.Write(signingKey)
	h.Write([]byte("shadow-cache"))
	var encryptKey [32]byte
	copy(encryptKey[:], h.Sum(nil))

	// Ensure base directory exists
	shadowDir := filepath.Join(baseDir, "shadows")
	if err := os.MkdirAll(shadowDir, 0700); err != nil {
		return nil, err
	}

	return &ShadowCache{
		baseDir:    shadowDir,
		encryptKey: encryptKey,
	}, nil
}

// Get retrieves the shadow for a file path, returns nil if not found.
func (sc *ShadowCache) Get(filePath string) (*ShadowFile, error) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	shadowPath := filepath.Join(sc.pathToDir(filePath), "current.shadow")

	ciphertext, err := os.ReadFile(shadowPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	plaintext, err := sc.decrypt(ciphertext)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	shadow, err := decodeShadow(plaintext)
	if err != nil {
		return nil, err
	}

	return shadow, nil
}

// Put stores a shadow for a file, choosing strategy based on size.
func (sc *ShadowCache) Put(filePath string, content []byte) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	// Determine strategy based on content size
	var strategy ShadowStrategy
	size := int64(len(content))

	switch {
	case size <= FullThreshold:
		strategy = ShadowFull
	case size <= ChunkedThreshold:
		strategy = ShadowChunked
	default:
		strategy = ShadowSize
	}

	// Create shadow file
	shadow := &ShadowFile{
		Version:     shadowVersion,
		ContentHash: sha256.Sum256(content),
		FileSize:    size,
		TimestampNs: time.Now().UnixNano(),
		Strategy:    strategy,
	}

	switch strategy {
	case ShadowFull:
		shadow.Content = make([]byte, len(content))
		copy(shadow.Content, content)
	case ShadowChunked:
		shadow.Chunks = computeChunks(content)
	case ShadowSize:
		// No additional data needed
	}

	// Encode and encrypt
	plaintext := encodeShadow(shadow)
	ciphertext, err := sc.encrypt(plaintext)
	if err != nil {
		return err
	}

	// Ensure directory exists and write file
	shadowDir := sc.pathToDir(filePath)
	if err := os.MkdirAll(shadowDir, 0700); err != nil {
		return err
	}

	shadowPath := filepath.Join(shadowDir, "current.shadow")
	return os.WriteFile(shadowPath, ciphertext, 0600)
}

// Delete removes a shadow for a file.
func (sc *ShadowCache) Delete(filePath string) error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	shadowDir := sc.pathToDir(filePath)
	shadowPath := filepath.Join(shadowDir, "current.shadow")

	err := os.Remove(shadowPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Try to remove the directory if empty
	_ = os.Remove(shadowDir)

	return nil
}

// pathToDir converts file path to shadow storage directory (using hash prefix).
func (sc *ShadowCache) pathToDir(filePath string) string {
	hash := sha256.Sum256([]byte(filePath))
	prefix := hex.EncodeToString(hash[:4]) // First 8 hex chars (4 bytes)
	return filepath.Join(sc.baseDir, prefix)
}

// encrypt encrypts plaintext using AES-256-GCM with random nonce.
func (sc *ShadowCache) encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(sc.encryptKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts ciphertext using AES-256-GCM.
func (sc *ShadowCache) decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceSize {
		return nil, ErrCorruptedShadow
	}

	block, err := aes.NewCipher(sc.encryptKey[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:nonceSize]
	ciphertextBody := ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertextBody, nil)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// encodeShadow serializes a ShadowFile to binary format.
func encodeShadow(s *ShadowFile) []byte {
	// Calculate required size
	size := 1 + 32 + 8 + 8 + 1 // version + hash + size + timestamp + strategy

	switch s.Strategy {
	case ShadowFull:
		size += 4 + len(s.Content) // length + content
	case ShadowChunked:
		size += 4 + len(s.Chunks)*48 // count + chunks (8+8+32 each)
	case ShadowSize:
		// No additional data
	}

	buf := make([]byte, size)
	offset := 0

	// Version
	buf[offset] = s.Version
	offset++

	// Content hash
	copy(buf[offset:offset+32], s.ContentHash[:])
	offset += 32

	// File size
	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(s.FileSize))
	offset += 8

	// Timestamp
	binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(s.TimestampNs))
	offset += 8

	// Strategy
	buf[offset] = uint8(s.Strategy)
	offset++

	switch s.Strategy {
	case ShadowFull:
		binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(s.Content)))
		offset += 4
		copy(buf[offset:], s.Content)

	case ShadowChunked:
		// Validate chunk count fits in uint32 (max 2^32-1 chunks)
		if len(s.Chunks) > 0xFFFFFFFF {
			// Truncate to max representable value - this is a safety limit
			binary.BigEndian.PutUint32(buf[offset:offset+4], 0xFFFFFFFF)
		} else {
			binary.BigEndian.PutUint32(buf[offset:offset+4], uint32(len(s.Chunks)))
		}
		offset += 4
		for _, chunk := range s.Chunks {
			binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(chunk.Offset))
			offset += 8
			binary.BigEndian.PutUint64(buf[offset:offset+8], uint64(chunk.Length))
			offset += 8
			copy(buf[offset:offset+32], chunk.Hash[:])
			offset += 32
		}

	case ShadowSize:
		// No additional data
	}

	return buf
}

// decodeShadow deserializes binary data to a ShadowFile.
func decodeShadow(data []byte) (*ShadowFile, error) {
	minSize := 1 + 32 + 8 + 8 + 1 // version + hash + size + timestamp + strategy
	if len(data) < minSize {
		return nil, ErrCorruptedShadow
	}

	offset := 0
	s := &ShadowFile{}

	// Version
	s.Version = data[offset]
	offset++

	if s.Version != shadowVersion {
		return nil, ErrInvalidVersion
	}

	// Content hash
	copy(s.ContentHash[:], data[offset:offset+32])
	offset += 32

	// File size
	s.FileSize = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Timestamp
	s.TimestampNs = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
	offset += 8

	// Strategy
	s.Strategy = ShadowStrategy(data[offset])
	offset++

	switch s.Strategy {
	case ShadowFull:
		if len(data) < offset+4 {
			return nil, ErrCorruptedShadow
		}
		contentLen := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if len(data) < offset+int(contentLen) {
			return nil, ErrCorruptedShadow
		}
		s.Content = make([]byte, contentLen)
		copy(s.Content, data[offset:offset+int(contentLen)])

	case ShadowChunked:
		if len(data) < offset+4 {
			return nil, ErrCorruptedShadow
		}
		chunkCount := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		expectedSize := offset + int(chunkCount)*48
		if len(data) < expectedSize {
			return nil, ErrCorruptedShadow
		}

		s.Chunks = make([]ChunkRef, chunkCount)
		for i := range s.Chunks {
			s.Chunks[i].Offset = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
			offset += 8
			s.Chunks[i].Length = int64(binary.BigEndian.Uint64(data[offset : offset+8]))
			offset += 8
			copy(s.Chunks[i].Hash[:], data[offset:offset+32])
			offset += 32
		}

	case ShadowSize:
		// No additional data

	default:
		return nil, ErrCorruptedShadow
	}

	return s, nil
}

// computeChunks uses content-defined chunking (Rabin fingerprint style).
// Target chunk size ~4KB, min 1KB, max 16KB.
func computeChunks(content []byte) []ChunkRef {
	if len(content) == 0 {
		return nil
	}

	var chunks []ChunkRef
	var offset int64 = 0
	contentLen := int64(len(content))

	for offset < contentLen {
		// Determine chunk boundary
		chunkEnd := findChunkBoundary(content, offset)

		// Create chunk reference
		chunkData := content[offset:chunkEnd]
		chunk := ChunkRef{
			Offset: offset,
			Length: int64(len(chunkData)),
			Hash:   sha256.Sum256(chunkData),
		}
		chunks = append(chunks, chunk)

		offset = chunkEnd
	}

	return chunks
}

// findChunkBoundary finds the next chunk boundary using a rolling hash.
func findChunkBoundary(content []byte, start int64) int64 {
	contentLen := int64(len(content))
	end := start + chunkMaxSize
	if end > contentLen {
		end = contentLen
	}

	// Minimum chunk size
	minEnd := start + chunkMinSize
	if minEnd > contentLen {
		return contentLen
	}

	// Use a simple rolling hash (Rabin-like)
	var hash uint32 = 0
	windowSize := 48 // Window size for rolling hash

	// Initialize hash with first window (starting from minimum position)
	pos := minEnd
	if pos-int64(windowSize) >= start {
		for i := pos - int64(windowSize); i < pos; i++ {
			hash = rollHash(hash, content[i])
		}
	} else {
		for i := start; i < pos; i++ {
			hash = rollHash(hash, content[i])
		}
	}

	// Scan for boundary
	for pos < end {
		hash = rollHash(hash, content[pos])

		// Check if we hit a boundary (hash matches mask pattern)
		if hash&chunkMask == 0 {
			return pos + 1
		}

		pos++
	}

	return end
}

// rollHash updates the rolling hash with a new byte.
func rollHash(hash uint32, b byte) uint32 {
	// Simple polynomial rolling hash
	return (hash << 1) ^ uint32(b)
}
