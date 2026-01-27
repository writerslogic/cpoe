//go:build windows

package ime

import "errors"

// WindowsPlatform implements the Platform interface for Windows.
// Uses Text Services Framework (TSF).
type WindowsPlatform struct {
	config PlatformConfig
	engine *Engine
}

// NewWindowsPlatform creates a new Windows IME platform.
func NewWindowsPlatform(config PlatformConfig, engine *Engine) *WindowsPlatform {
	return &WindowsPlatform{
		config: config,
		engine: engine,
	}
}

func (p *WindowsPlatform) Name() string {
	return "windows"
}

func (p *WindowsPlatform) Available() bool {
	return true
}

func (p *WindowsPlatform) Install() error {
	// TSF installation requires:
	// 1. Register COM DLL with regsvr32
	// 2. Add registry entries under HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\CTF\TIP
	// 3. Register CLSID and language profile
	return errors.New("not implemented: Windows TSF installation requires administrator privileges")
}

func (p *WindowsPlatform) Uninstall() error {
	return errors.New("not implemented")
}

func (p *WindowsPlatform) IsInstalled() bool {
	return false
}

func (p *WindowsPlatform) IsActive() bool {
	return false
}

func (p *WindowsPlatform) Activate() error {
	return errors.New("not implemented: use Windows Settings to select input method")
}

// WindowsZoneMapping provides Windows-specific virtual key code mapping.
// Uses Windows VK_* constants.
type WindowsZoneMapping struct{}

func (WindowsZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// Windows virtual key codes (VK_*)
	// VK_A = 0x41, VK_Z = 0x5A
	switch keyCode {
	// Zone 0: Left pinky - Q(0x51), A(0x41), Z(0x5A)
	case 0x51, 0x41, 0x5A:
		return 0
	// Zone 1: Left ring - W(0x57), S(0x53), X(0x58)
	case 0x57, 0x53, 0x58:
		return 1
	// Zone 2: Left middle - E(0x45), D(0x44), C(0x43)
	case 0x45, 0x44, 0x43:
		return 2
	// Zone 3: Left index - R(0x52), T(0x54), F(0x46), G(0x47), V(0x56), B(0x42)
	case 0x52, 0x54, 0x46, 0x47, 0x56, 0x42:
		return 3
	// Zone 4: Right index - Y(0x59), U(0x55), H(0x48), J(0x4A), N(0x4E), M(0x4D)
	case 0x59, 0x55, 0x48, 0x4A, 0x4E, 0x4D:
		return 4
	// Zone 5: Right middle - I(0x49), K(0x4B), comma(0xBC)
	case 0x49, 0x4B, 0xBC:
		return 5
	// Zone 6: Right ring - O(0x4F), L(0x4C), period(0xBE)
	case 0x4F, 0x4C, 0xBE:
		return 6
	// Zone 7: Right pinky - P(0x50), semicolon(0xBA), slash(0xBF)
	case 0x50, 0xBA, 0xBF:
		return 7
	default:
		return -1
	}
}

func (WindowsZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

var _ Platform = (*WindowsPlatform)(nil)
