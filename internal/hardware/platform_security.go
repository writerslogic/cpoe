// Package hardware provides platform security state capture.
//
// This file captures the security state of the platform at runtime,
// providing evidence of the execution environment's integrity.
package hardware

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// PlatformSecurityState captures the security configuration of the platform.
type PlatformSecurityState struct {
	// Capture metadata
	CapturedAt time.Time `json:"captured_at"`
	Platform   string    `json:"platform"`
	Arch       string    `json:"arch"`

	// Boot security
	SecureBoot      *bool  `json:"secure_boot,omitempty"`
	MeasuredBoot    *bool  `json:"measured_boot,omitempty"`
	BootMode        string `json:"boot_mode,omitempty"` // "UEFI", "BIOS", "unknown"

	// Kernel security
	KernelLockdown  string `json:"kernel_lockdown,omitempty"` // "none", "integrity", "confidentiality"
	KernelVersion   string `json:"kernel_version,omitempty"`
	KernelSigned    *bool  `json:"kernel_signed,omitempty"`

	// macOS-specific
	SIPEnabled      *bool  `json:"sip_enabled,omitempty"`       // System Integrity Protection
	GatekeeperOn    *bool  `json:"gatekeeper_enabled,omitempty"`
	FileVaultOn     *bool  `json:"filevault_enabled,omitempty"`

	// Linux-specific
	SELinuxMode     string `json:"selinux_mode,omitempty"`     // "enforcing", "permissive", "disabled"
	AppArmorStatus  string `json:"apparmor_status,omitempty"`

	// Windows-specific
	BitLockerOn     *bool  `json:"bitlocker_enabled,omitempty"`
	SecureBootDB    string `json:"secure_boot_db,omitempty"`

	// Virtualization detection
	IsVirtualized   *bool  `json:"is_virtualized,omitempty"`
	HypervisorType  string `json:"hypervisor_type,omitempty"` // "none", "vmware", "hyperv", "kvm", "xen", "unknown"

	// Process security
	ProcessUID      int    `json:"process_uid"`
	ProcessEUID     int    `json:"process_euid"`
	ProcessIsRoot   bool   `json:"process_is_root"`
	Debugger        *bool  `json:"debugger_attached,omitempty"`

	// Binary integrity
	ExecutablePath  string `json:"executable_path,omitempty"`
	ExecutableHash  string `json:"executable_hash,omitempty"`

	// Network state (relevant to clock attacks)
	NTPSynced       *bool  `json:"ntp_synced,omitempty"`

	// Warnings and limitations
	Warnings        []string `json:"warnings,omitempty"`
	Limitations     []string `json:"limitations,omitempty"`
}

// CapturePlatformSecurityState captures the current platform security state.
func CapturePlatformSecurityState() *PlatformSecurityState {
	state := &PlatformSecurityState{
		CapturedAt:    time.Now(),
		Platform:      runtime.GOOS,
		Arch:          runtime.GOARCH,
		ProcessUID:    os.Getuid(),
		ProcessEUID:   os.Geteuid(),
		ProcessIsRoot: os.Geteuid() == 0,
	}

	// Get executable path and hash
	if exe, err := os.Executable(); err == nil {
		state.ExecutablePath = exe
		if data, err := os.ReadFile(exe); err == nil {
			hash := sha256.Sum256(data)
			state.ExecutableHash = string(hash[:])
		}
	}

	// Platform-specific captures
	switch runtime.GOOS {
	case "darwin":
		captureDarwinSecurity(state)
	case "linux":
		captureLinuxSecurity(state)
	case "windows":
		captureWindowsSecurity(state)
	}

	// Check for virtualization
	detectVirtualization(state)

	// Add limitations
	state.Limitations = []string{
		"Security state reflects point-in-time capture only",
		"Kernel-level compromise can falsify all values",
		"Virtualization detection can be bypassed by sophisticated hypervisors",
	}

	return state
}

// captureDarwinSecurity captures macOS-specific security state.
func captureDarwinSecurity(state *PlatformSecurityState) {
	// Check SIP status
	if out, err := exec.Command("csrutil", "status").Output(); err == nil {
		enabled := strings.Contains(string(out), "enabled")
		state.SIPEnabled = &enabled
		if !enabled {
			state.Warnings = append(state.Warnings, "System Integrity Protection is disabled")
		}
	}

	// Check boot mode
	if out, err := exec.Command("system_profiler", "SPSoftwareDataType").Output(); err == nil {
		if strings.Contains(string(out), "Secure Boot") {
			state.BootMode = "UEFI"
			// Check for secure boot
			if strings.Contains(string(out), "Full Security") {
				t := true
				state.SecureBoot = &t
			}
		}
	}

	// Check kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		state.KernelVersion = strings.TrimSpace(string(out))
	}
}

// captureLinuxSecurity captures Linux-specific security state.
func captureLinuxSecurity(state *PlatformSecurityState) {
	// Check kernel lockdown
	if data, err := os.ReadFile("/sys/kernel/security/lockdown"); err == nil {
		lockdown := strings.TrimSpace(string(data))
		// Format: "[none] integrity confidentiality"
		if strings.Contains(lockdown, "[none]") {
			state.KernelLockdown = "none"
		} else if strings.Contains(lockdown, "[integrity]") {
			state.KernelLockdown = "integrity"
		} else if strings.Contains(lockdown, "[confidentiality]") {
			state.KernelLockdown = "confidentiality"
		}

		if state.KernelLockdown == "none" || state.KernelLockdown == "" {
			state.Warnings = append(state.Warnings, "Kernel lockdown is not enabled")
		}
	}

	// Check SELinux
	if out, err := exec.Command("getenforce").Output(); err == nil {
		state.SELinuxMode = strings.TrimSpace(string(out))
		if state.SELinuxMode != "Enforcing" {
			state.Warnings = append(state.Warnings, "SELinux is not in enforcing mode")
		}
	}

	// Check Secure Boot
	if data, err := os.ReadFile("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"); err == nil {
		// Last byte indicates status: 1 = enabled
		if len(data) > 0 && data[len(data)-1] == 1 {
			t := true
			state.SecureBoot = &t
		} else {
			f := false
			state.SecureBoot = &f
			state.Warnings = append(state.Warnings, "Secure Boot is disabled")
		}
	}

	// Check kernel version
	if out, err := exec.Command("uname", "-r").Output(); err == nil {
		state.KernelVersion = strings.TrimSpace(string(out))
	}

	// Check for debugger
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		if strings.Contains(string(data), "TracerPid:\t0") {
			f := false
			state.Debugger = &f
		} else {
			t := true
			state.Debugger = &t
			state.Warnings = append(state.Warnings, "Process is being traced/debugged")
		}
	}
}

// captureWindowsSecurity captures Windows-specific security state.
func captureWindowsSecurity(state *PlatformSecurityState) {
	// Check Secure Boot via PowerShell
	if out, err := exec.Command("powershell", "-Command", "Confirm-SecureBootUEFI").Output(); err == nil {
		enabled := strings.TrimSpace(string(out)) == "True"
		state.SecureBoot = &enabled
		if !enabled {
			state.Warnings = append(state.Warnings, "Secure Boot is disabled")
		}
	}

	// Check kernel version
	if out, err := exec.Command("cmd", "/c", "ver").Output(); err == nil {
		state.KernelVersion = strings.TrimSpace(string(out))
	}
}

// detectVirtualization checks if running in a virtual machine.
func detectVirtualization(state *PlatformSecurityState) {
	isVirt := false
	hypervisor := "none"

	switch runtime.GOOS {
	case "linux":
		// Check DMI
		if data, err := os.ReadFile("/sys/class/dmi/id/product_name"); err == nil {
			product := strings.ToLower(string(data))
			if strings.Contains(product, "vmware") {
				isVirt = true
				hypervisor = "vmware"
			} else if strings.Contains(product, "virtual") {
				isVirt = true
				hypervisor = "hyperv"
			} else if strings.Contains(product, "kvm") {
				isVirt = true
				hypervisor = "kvm"
			} else if strings.Contains(product, "xen") {
				isVirt = true
				hypervisor = "xen"
			}
		}

		// Check cpuinfo for hypervisor flag
		if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			if strings.Contains(string(data), "hypervisor") {
				isVirt = true
				if hypervisor == "none" {
					hypervisor = "unknown"
				}
			}
		}

	case "darwin":
		// Check sysctl
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.features").Output(); err == nil {
			if strings.Contains(string(out), "VMM") {
				isVirt = true
				hypervisor = "unknown"
			}
		}
		// Check for specific VM identifiers
		if out, err := exec.Command("ioreg", "-l").Output(); err == nil {
			outStr := strings.ToLower(string(out))
			if strings.Contains(outStr, "vmware") {
				isVirt = true
				hypervisor = "vmware"
			} else if strings.Contains(outStr, "parallels") {
				isVirt = true
				hypervisor = "parallels"
			} else if strings.Contains(outStr, "virtualbox") {
				isVirt = true
				hypervisor = "virtualbox"
			}
		}
	}

	state.IsVirtualized = &isVirt
	state.HypervisorType = hypervisor

	if isVirt {
		state.Warnings = append(state.Warnings,
			"Running in virtualized environment - VM snapshots can manipulate state")
	}
}

// Hash returns a cryptographic hash of the security state.
func (s *PlatformSecurityState) Hash() [32]byte {
	data, _ := json.Marshal(s)
	return sha256.Sum256(data)
}

// IsSecure returns true if no critical security warnings are present.
func (s *PlatformSecurityState) IsSecure() bool {
	// Check for critical issues
	if s.SIPEnabled != nil && !*s.SIPEnabled {
		return false
	}
	if s.SecureBoot != nil && !*s.SecureBoot {
		return false
	}
	if s.KernelLockdown == "none" {
		return false
	}
	if s.Debugger != nil && *s.Debugger {
		return false
	}
	if s.IsVirtualized != nil && *s.IsVirtualized {
		return false
	}
	return true
}

// SecurityScore returns a 0-100 score of platform security.
func (s *PlatformSecurityState) SecurityScore() int {
	score := 100

	// Deductions
	if s.SIPEnabled != nil && !*s.SIPEnabled {
		score -= 20
	}
	if s.SecureBoot != nil && !*s.SecureBoot {
		score -= 20
	}
	if s.KernelLockdown == "none" || s.KernelLockdown == "" {
		score -= 15
	}
	if s.Debugger != nil && *s.Debugger {
		score -= 25
	}
	if s.IsVirtualized != nil && *s.IsVirtualized {
		score -= 15
	}
	if s.ProcessIsRoot {
		score -= 5 // Running as root is a minor concern
	}

	if score < 0 {
		score = 0
	}
	return score
}
