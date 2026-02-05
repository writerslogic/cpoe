// Package evidence implements forensic evidence integrity enforcement.
//
// This file implements the Evidence Architecture Specification, creating
// inescapable dilemmas for challengers rather than merely "secure" systems.
package evidence

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// EvidenceClass indicates the reliability class of evidence.
type EvidenceClass string

const (
	// ClassA - Full integrity, all invariants satisfied. Suitable for forensic reliance.
	ClassA EvidenceClass = "A"
	// ClassB - Minor warnings, no invariant violations. Suitable for general use.
	ClassB EvidenceClass = "B"
	// ClassC - Suspicious patterns detected. Review required.
	ClassC EvidenceClass = "C"
	// ClassD - Invariant violated. Not suitable for forensic reliance.
	ClassD EvidenceClass = "D"
	// ClassX - Verification failed. Rejected.
	ClassX EvidenceClass = "X"
)

// CaptureEnvironmentDeclaration is sworn-fact-surrogate testimony about
// the execution environment at capture time.
//
// Frame: "These were the observable properties of the system at time T.
// If they are false, then either (a) our capture mechanism was falsified,
// or (b) the environment behaved inconsistently with itself."
type CaptureEnvironmentDeclaration struct {
	// Capture metadata
	CapturedAt      time.Time `json:"captured_at"`
	MonotonicClockNS int64    `json:"monotonic_clock_ns"`
	WallClockNS     int64     `json:"wall_clock_ns"`

	// OS identification
	OSName          string  `json:"os_name"`
	OSVersion       string  `json:"os_version"`
	KernelVersion   string  `json:"kernel_version"`
	Architecture    string  `json:"architecture"`

	// Security state (null = unavailable, not unchecked)
	SecureBoot      *bool   `json:"secure_boot"`
	TPMPresent      bool    `json:"tpm_present"`
	TPMVersion      *string `json:"tpm_version"`

	// Virtualization
	VirtualizationDetected bool   `json:"virtualization_detected"`
	HypervisorType         string `json:"hypervisor_type"`

	// Platform-specific
	SIPEnabled      *bool   `json:"sip_enabled,omitempty"`      // macOS
	KernelLockdown  *string `json:"kernel_lockdown,omitempty"`  // Linux

	// Process identity
	ProcessUID      int     `json:"process_uid"`
	ProcessEUID     int     `json:"process_euid"`
	ExecutableHash  string  `json:"executable_hash"`

	// Network time
	NTPOffsetMS     *int64  `json:"ntp_offset_ms"`

	// Explicit negatives - what we checked and found absent
	ExplicitNegatives []string `json:"explicit_negatives"`

	// Hash of this declaration (set after creation)
	Hash            [32]byte `json:"hash"`
}

// NewCaptureEnvironmentDeclaration captures the current environment state.
func NewCaptureEnvironmentDeclaration() *CaptureEnvironmentDeclaration {
	now := time.Now()

	ced := &CaptureEnvironmentDeclaration{
		CapturedAt:       now,
		MonotonicClockNS: now.UnixNano(), // Best approximation without cgo
		WallClockNS:      now.UnixNano(),
		OSName:           runtime.GOOS,
		Architecture:     runtime.GOARCH,
		ProcessUID:       os.Getuid(),
		ProcessEUID:      os.Geteuid(),
		ExplicitNegatives: []string{},
	}

	// Capture executable hash
	if exe, err := os.Executable(); err == nil {
		if data, err := os.ReadFile(exe); err == nil {
			hash := sha256.Sum256(data)
			ced.ExecutableHash = fmt.Sprintf("%x", hash)
		}
	}

	// Platform-specific capture
	switch runtime.GOOS {
	case "darwin":
		captureDarwinCED(ced)
	case "linux":
		captureLinuxCED(ced)
	case "windows":
		captureWindowsCED(ced)
	}

	// Detect virtualization
	detectVirtualizationCED(ced)

	// Check TPM
	checkTPMCED(ced)

	// Compute hash
	ced.computeHash()

	return ced
}

func captureDarwinCED(ced *CaptureEnvironmentDeclaration) {
	// OS version
	if out, err := exec.Command("sw_vers", "-productVersion").Output(); err == nil {
		ced.OSVersion = strings.TrimSpace(string(out))
	} else {
		ced.OSVersion = "unknown"
	}

	// Kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		ced.KernelVersion = strings.TrimSpace(string(out))
	} else {
		ced.KernelVersion = "unknown"
	}

	// SIP status
	if out, err := exec.Command("csrutil", "status").Output(); err == nil {
		enabled := strings.Contains(string(out), "enabled")
		ced.SIPEnabled = &enabled
		if !enabled {
			ced.ExplicitNegatives = append(ced.ExplicitNegatives,
				"System Integrity Protection disabled")
		}
	} else {
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			"SIP status unavailable")
	}

	// Secure Boot - check via nvram on Apple Silicon
	if out, err := exec.Command("system_profiler", "SPiBridgeDataType").Output(); err == nil {
		if strings.Contains(string(out), "Secure Boot") {
			t := true
			ced.SecureBoot = &t
		}
	}
	if ced.SecureBoot == nil {
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			"Secure Boot status unavailable")
	}
}

func captureLinuxCED(ced *CaptureEnvironmentDeclaration) {
	// OS version
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "VERSION=") {
				ced.OSVersion = strings.Trim(strings.TrimPrefix(line, "VERSION="), "\"")
				break
			}
		}
	}
	if ced.OSVersion == "" {
		ced.OSVersion = "unknown"
	}

	// Kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		ced.KernelVersion = strings.TrimSpace(string(out))
	} else {
		ced.KernelVersion = "unknown"
	}

	// Kernel lockdown
	if data, err := os.ReadFile("/sys/kernel/security/lockdown"); err == nil {
		lockdown := strings.TrimSpace(string(data))
		if strings.Contains(lockdown, "[none]") {
			s := "none"
			ced.KernelLockdown = &s
			ced.ExplicitNegatives = append(ced.ExplicitNegatives,
				"Kernel lockdown not enabled")
		} else if strings.Contains(lockdown, "[integrity]") {
			s := "integrity"
			ced.KernelLockdown = &s
		} else if strings.Contains(lockdown, "[confidentiality]") {
			s := "confidentiality"
			ced.KernelLockdown = &s
		}
	} else {
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			"Kernel lockdown status unavailable")
	}

	// Secure Boot
	if data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil {
		if len(data) > 0 && data[len(data)-1] == 1 {
			t := true
			ced.SecureBoot = &t
		} else {
			f := false
			ced.SecureBoot = &f
			ced.ExplicitNegatives = append(ced.ExplicitNegatives,
				"Secure Boot disabled")
		}
	} else {
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			"Secure Boot status unavailable")
	}
}

func captureWindowsCED(ced *CaptureEnvironmentDeclaration) {
	// OS version
	if out, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
		ced.OSVersion = strings.TrimSpace(string(out))
	} else {
		ced.OSVersion = "unknown"
	}

	ced.KernelVersion = ced.OSVersion // Windows conflates these

	// Secure Boot
	if out, err := exec.Command("powershell", "-Command", "Confirm-SecureBootUEFI").Output(); err == nil {
		enabled := strings.TrimSpace(string(out)) == "True"
		ced.SecureBoot = &enabled
		if !enabled {
			ced.ExplicitNegatives = append(ced.ExplicitNegatives,
				"Secure Boot disabled")
		}
	} else {
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			"Secure Boot status unavailable")
	}
}

func detectVirtualizationCED(ced *CaptureEnvironmentDeclaration) {
	ced.HypervisorType = "none"

	switch runtime.GOOS {
	case "linux":
		// Check DMI
		if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			product := strings.ToLower(string(data))
			if strings.Contains(product, "vmware") {
				ced.VirtualizationDetected = true
				ced.HypervisorType = "vmware"
			} else if strings.Contains(product, "virtual") {
				ced.VirtualizationDetected = true
				ced.HypervisorType = "hyperv"
			} else if strings.Contains(product, "kvm") {
				ced.VirtualizationDetected = true
				ced.HypervisorType = "kvm"
			} else if strings.Contains(product, "xen") {
				ced.VirtualizationDetected = true
				ced.HypervisorType = "xen"
			}
		}

		// Check cpuinfo
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			if strings.Contains(string(data), "hypervisor") {
				ced.VirtualizationDetected = true
				if ced.HypervisorType == "none" {
					ced.HypervisorType = "unknown"
				}
			}
		}

	case "darwin":
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.features").Output(); err == nil {
			if strings.Contains(string(out), "VMM") {
				ced.VirtualizationDetected = true
				ced.HypervisorType = "unknown"
			}
		}
	}

	if ced.VirtualizationDetected {
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			fmt.Sprintf("Virtualization detected: %s", ced.HypervisorType))
	}
}

func checkTPMCED(ced *CaptureEnvironmentDeclaration) {
	// Platform-specific TPM detection
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat("/dev/tpm0"); err == nil {
			ced.TPMPresent = true
			v := "2.0" // Assume 2.0 if present
			ced.TPMVersion = &v
		} else {
			ced.ExplicitNegatives = append(ced.ExplicitNegatives,
				"TPM not available")
		}
	case "darwin":
		// macOS uses Secure Enclave, not TPM
		ced.ExplicitNegatives = append(ced.ExplicitNegatives,
			"TPM not available (macOS uses Secure Enclave)")
	case "windows":
		if out, err := exec.Command("powershell", "-Command",
			"Get-Tpm | Select-Object -ExpandProperty TpmPresent").Output(); err == nil {
			if strings.TrimSpace(string(out)) == "True" {
				ced.TPMPresent = true
				v := "2.0"
				ced.TPMVersion = &v
			}
		}
		if !ced.TPMPresent {
			ced.ExplicitNegatives = append(ced.ExplicitNegatives,
				"TPM not available")
		}
	}
}

func (ced *CaptureEnvironmentDeclaration) computeHash() {
	// Create canonical JSON (excluding Hash field)
	type hashable struct {
		CapturedAt             time.Time `json:"captured_at"`
		MonotonicClockNS       int64     `json:"monotonic_clock_ns"`
		WallClockNS            int64     `json:"wall_clock_ns"`
		OSName                 string    `json:"os_name"`
		OSVersion              string    `json:"os_version"`
		KernelVersion          string    `json:"kernel_version"`
		Architecture           string    `json:"architecture"`
		SecureBoot             *bool     `json:"secure_boot"`
		TPMPresent             bool      `json:"tpm_present"`
		TPMVersion             *string   `json:"tpm_version"`
		VirtualizationDetected bool      `json:"virtualization_detected"`
		HypervisorType         string    `json:"hypervisor_type"`
		SIPEnabled             *bool     `json:"sip_enabled,omitempty"`
		KernelLockdown         *string   `json:"kernel_lockdown,omitempty"`
		ProcessUID             int       `json:"process_uid"`
		ProcessEUID            int       `json:"process_euid"`
		ExecutableHash         string    `json:"executable_hash"`
		NTPOffsetMS            *int64    `json:"ntp_offset_ms"`
		ExplicitNegatives      []string  `json:"explicit_negatives"`
	}

	h := hashable{
		CapturedAt:             ced.CapturedAt,
		MonotonicClockNS:       ced.MonotonicClockNS,
		WallClockNS:            ced.WallClockNS,
		OSName:                 ced.OSName,
		OSVersion:              ced.OSVersion,
		KernelVersion:          ced.KernelVersion,
		Architecture:           ced.Architecture,
		SecureBoot:             ced.SecureBoot,
		TPMPresent:             ced.TPMPresent,
		TPMVersion:             ced.TPMVersion,
		VirtualizationDetected: ced.VirtualizationDetected,
		HypervisorType:         ced.HypervisorType,
		SIPEnabled:             ced.SIPEnabled,
		KernelLockdown:         ced.KernelLockdown,
		ProcessUID:             ced.ProcessUID,
		ProcessEUID:            ced.ProcessEUID,
		ExecutableHash:         ced.ExecutableHash,
		NTPOffsetMS:            ced.NTPOffsetMS,
		ExplicitNegatives:      ced.ExplicitNegatives,
	}

	data, _ := json.Marshal(h)
	ced.Hash = sha256.Sum256(data)
}

// InvariantViolation records a detected invariant violation.
type InvariantViolation struct {
	DetectedAt  time.Time `json:"detected_at"`
	Invariant   string    `json:"invariant"`
	Expected    string    `json:"expected"`
	Actual      string    `json:"actual"`
	Consequence string    `json:"consequence"`
	Hash        [32]byte  `json:"hash"`
}

// InvariantEnforcer tracks and enforces evidence invariants.
type InvariantEnforcer struct {
	mu sync.Mutex

	// State for invariant checking
	lastMonotonicTime int64
	lastWallTime      int64
	lastChainHash     [32]byte
	cedHash           [32]byte

	// Recorded violations
	violations []InvariantViolation

	// Current evidence class
	class EvidenceClass
}

// NewInvariantEnforcer creates a new enforcer bound to a CED.
func NewInvariantEnforcer(ced *CaptureEnvironmentDeclaration) *InvariantEnforcer {
	return &InvariantEnforcer{
		lastMonotonicTime: ced.MonotonicClockNS,
		lastWallTime:      ced.WallClockNS,
		cedHash:           ced.Hash,
		class:             ClassA,
	}
}

// CheckMonotonicTime verifies time never decreases.
func (ie *InvariantEnforcer) CheckMonotonicTime(currentNS int64) error {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	if currentNS < ie.lastMonotonicTime {
		violation := InvariantViolation{
			DetectedAt:  time.Now(),
			Invariant:   "monotonic_time_never_decreases",
			Expected:    fmt.Sprintf(">= %d", ie.lastMonotonicTime),
			Actual:      fmt.Sprintf("%d", currentNS),
			Consequence: "Clock manipulation detected",
		}
		violation.computeHash()
		ie.violations = append(ie.violations, violation)
		ie.class = ClassD
		return errors.New("invariant violation: monotonic time decreased")
	}

	ie.lastMonotonicTime = currentNS
	return nil
}

// CheckChainContinuity verifies hash chain never forks.
func (ie *InvariantEnforcer) CheckChainContinuity(prevHash, currentHash [32]byte) error {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	// First hash
	if ie.lastChainHash == [32]byte{} {
		ie.lastChainHash = currentHash
		return nil
	}

	// Verify continuity
	if prevHash != ie.lastChainHash {
		violation := InvariantViolation{
			DetectedAt:  time.Now(),
			Invariant:   "hash_chain_never_forks",
			Expected:    fmt.Sprintf("%x", ie.lastChainHash),
			Actual:      fmt.Sprintf("%x", prevHash),
			Consequence: "Chain fork detected - data tampering",
		}
		violation.computeHash()
		ie.violations = append(ie.violations, violation)
		ie.class = ClassD
		return errors.New("invariant violation: hash chain fork detected")
	}

	ie.lastChainHash = currentHash
	return nil
}

// CheckAnchorTime verifies external anchor time >= last local time.
func (ie *InvariantEnforcer) CheckAnchorTime(anchorTimeNS, localTimeNS int64) error {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	if anchorTimeNS < localTimeNS {
		violation := InvariantViolation{
			DetectedAt:  time.Now(),
			Invariant:   "anchor_time_gte_local_time",
			Expected:    fmt.Sprintf(">= %d", localTimeNS),
			Actual:      fmt.Sprintf("%d", anchorTimeNS),
			Consequence: "External anchor predates local event - future-dating attempt",
		}
		violation.computeHash()
		ie.violations = append(ie.violations, violation)
		if ie.class < ClassC {
			ie.class = ClassC
		}
		return errors.New("invariant violation: anchor time before local time")
	}

	return nil
}

// CheckCEDConsistency verifies environment fingerprint is constant.
func (ie *InvariantEnforcer) CheckCEDConsistency(currentCEDHash [32]byte) error {
	ie.mu.Lock()
	defer ie.mu.Unlock()

	if currentCEDHash != ie.cedHash {
		violation := InvariantViolation{
			DetectedAt:  time.Now(),
			Invariant:   "ced_fingerprint_constant",
			Expected:    fmt.Sprintf("%x", ie.cedHash),
			Actual:      fmt.Sprintf("%x", currentCEDHash),
			Consequence: "Environment changed during session",
		}
		violation.computeHash()
		ie.violations = append(ie.violations, violation)
		if ie.class < ClassC {
			ie.class = ClassC
		}
		return errors.New("invariant violation: environment fingerprint changed")
	}

	return nil
}

// Class returns the current evidence class.
func (ie *InvariantEnforcer) Class() EvidenceClass {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	return ie.class
}

// Violations returns all recorded violations.
func (ie *InvariantEnforcer) Violations() []InvariantViolation {
	ie.mu.Lock()
	defer ie.mu.Unlock()
	result := make([]InvariantViolation, len(ie.violations))
	copy(result, ie.violations)
	return result
}

func (v *InvariantViolation) computeHash() {
	h := sha256.New()
	h.Write([]byte(v.Invariant))
	h.Write([]byte(v.Expected))
	h.Write([]byte(v.Actual))
	binary.Write(h, binary.BigEndian, v.DetectedAt.UnixNano())
	copy(v.Hash[:], h.Sum(nil))
}

// NegativeEvidence records what should have happened but didn't.
type NegativeEvidence struct {
	Assertion   string    `json:"assertion"`
	Period      [2]int64  `json:"period_ns"` // [start, end]
	Computed    bool      `json:"computed"`  // Not assumed
	Hash        [32]byte  `json:"hash"`
}

// ComputeNegativeEvidence computes assertions about absence.
func ComputeNegativeEvidence(assertion string, startNS, endNS int64) NegativeEvidence {
	ne := NegativeEvidence{
		Assertion: assertion,
		Period:    [2]int64{startNS, endNS},
		Computed:  true,
	}

	h := sha256.New()
	h.Write([]byte("negative-evidence-v1"))
	h.Write([]byte(assertion))
	binary.Write(h, binary.BigEndian, startNS)
	binary.Write(h, binary.BigEndian, endNS)
	copy(ne.Hash[:], h.Sum(nil))

	return ne
}

// KeyLifecycle tracks the lifecycle of a signing key.
type KeyLifecycle struct {
	KeyID          [32]byte  `json:"key_id"`
	GeneratedAt    time.Time `json:"generated_at"`
	FirstUse       time.Time `json:"first_use"`
	LastUse        time.Time `json:"last_use"`
	DestroyedAt    *time.Time `json:"destroyed_at"`
	OperationCount int       `json:"operation_count"`
	Hash           [32]byte  `json:"hash"`
}

// NewKeyLifecycle creates a new key lifecycle tracker.
func NewKeyLifecycle(keyID [32]byte) *KeyLifecycle {
	now := time.Now()
	return &KeyLifecycle{
		KeyID:       keyID,
		GeneratedAt: now,
	}
}

// RecordUse records a key use operation.
func (kl *KeyLifecycle) RecordUse() {
	now := time.Now()
	if kl.FirstUse.IsZero() {
		kl.FirstUse = now
	}
	kl.LastUse = now
	kl.OperationCount++
}

// RecordDestruction records key destruction.
func (kl *KeyLifecycle) RecordDestruction() {
	now := time.Now()
	kl.DestroyedAt = &now
	kl.computeHash()
}

func (kl *KeyLifecycle) computeHash() {
	h := sha256.New()
	h.Write([]byte("key-lifecycle-v1"))
	h.Write(kl.KeyID[:])
	binary.Write(h, binary.BigEndian, kl.GeneratedAt.UnixNano())
	binary.Write(h, binary.BigEndian, kl.FirstUse.UnixNano())
	binary.Write(h, binary.BigEndian, kl.LastUse.UnixNano())
	if kl.DestroyedAt != nil {
		binary.Write(h, binary.BigEndian, kl.DestroyedAt.UnixNano())
	}
	binary.Write(h, binary.BigEndian, int64(kl.OperationCount))
	copy(kl.Hash[:], h.Sum(nil))
}

// ValidateLifecycle checks key lifecycle consistency.
func (kl *KeyLifecycle) ValidateLifecycle() error {
	if !kl.FirstUse.IsZero() && kl.FirstUse.Before(kl.GeneratedAt) {
		return errors.New("lifecycle violation: first use before generation")
	}
	if kl.LastUse.Before(kl.FirstUse) {
		return errors.New("lifecycle violation: last use before first use")
	}
	if kl.DestroyedAt != nil && kl.DestroyedAt.Before(kl.LastUse) {
		return errors.New("lifecycle violation: destruction before last use")
	}
	return nil
}

// EvidenceClassification contains the final classification of evidence.
type EvidenceClassification struct {
	Class       EvidenceClass `json:"class"`
	Reason      string        `json:"reason"`
	Violations  []string      `json:"violations,omitempty"`
	Warnings    []string      `json:"warnings,omitempty"`
	SuitableFor string        `json:"suitable_for"`
}

// ClassifyEvidence determines the evidence class based on all checks.
func ClassifyEvidence(enforcer *InvariantEnforcer, lifecycle *KeyLifecycle) EvidenceClassification {
	class := enforcer.Class()
	violations := enforcer.Violations()

	classification := EvidenceClassification{
		Class: class,
	}

	// Check key lifecycle
	if lifecycle != nil {
		if err := lifecycle.ValidateLifecycle(); err != nil {
			class = ClassD
			classification.Violations = append(classification.Violations, err.Error())
		}
	}

	// Add violation descriptions
	for _, v := range violations {
		classification.Violations = append(classification.Violations,
			fmt.Sprintf("%s: %s", v.Invariant, v.Consequence))
	}

	// Set reason and suitability
	switch class {
	case ClassA:
		classification.Reason = "All invariants satisfied, no violations detected"
		classification.SuitableFor = "Forensic reliance"
	case ClassB:
		classification.Reason = "Minor warnings present, no invariant violations"
		classification.SuitableFor = "General use"
	case ClassC:
		classification.Reason = "Suspicious patterns detected"
		classification.SuitableFor = "Review required before reliance"
	case ClassD:
		classification.Reason = "Invariant violated"
		classification.SuitableFor = "NOT suitable for forensic reliance"
	case ClassX:
		classification.Reason = "Verification failed"
		classification.SuitableFor = "Rejected"
	}

	classification.Class = class
	return classification
}
