//go:build darwin

package ime

import (
	"errors"
	"os"
	"path/filepath"
)

// DarwinPlatform implements the Platform interface for macOS.
// Uses Input Method Kit (IMKit) framework.
type DarwinPlatform struct {
	config PlatformConfig
	engine *Engine
}

// NewDarwinPlatform creates a new macOS IME platform.
func NewDarwinPlatform(config PlatformConfig, engine *Engine) *DarwinPlatform {
	if config.BundleID == "" {
		config.BundleID = "com.witnessd.inputmethod"
	}
	if config.DisplayName == "" {
		config.DisplayName = "Witnessd"
	}
	return &DarwinPlatform{
		config: config,
		engine: engine,
	}
}

func (p *DarwinPlatform) Name() string {
	return "macos"
}

func (p *DarwinPlatform) Available() bool {
	// macOS is always available when we're compiled for darwin
	return true
}

// Install creates the input method bundle and registers it.
// The bundle structure:
//
//	Witnessd.app/
//	├── Contents/
//	│   ├── Info.plist
//	│   ├── MacOS/
//	│   │   └── Witnessd
//	│   └── Resources/
//	│       └── icon.icns
func (p *DarwinPlatform) Install() error {
	// Get install location (~/Library/Input Methods/)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	installDir := filepath.Join(home, "Library", "Input Methods")
	bundlePath := filepath.Join(installDir, "Witnessd.app")

	// Create bundle structure
	dirs := []string{
		filepath.Join(bundlePath, "Contents", "MacOS"),
		filepath.Join(bundlePath, "Contents", "Resources"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// Create Info.plist
	plistPath := filepath.Join(bundlePath, "Contents", "Info.plist")
	plist := p.generateInfoPlist()
	if err := os.WriteFile(plistPath, []byte(plist), 0644); err != nil {
		return err
	}

	// Copy the current executable as the input method binary
	// In a real implementation, we'd have a separate IME binary
	execPath, err := os.Executable()
	if err != nil {
		return err
	}

	destExec := filepath.Join(bundlePath, "Contents", "MacOS", "Witnessd")
	if err := copyFile(execPath, destExec); err != nil {
		return err
	}
	if err := os.Chmod(destExec, 0755); err != nil {
		return err
	}

	return nil
}

func (p *DarwinPlatform) Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	bundlePath := filepath.Join(home, "Library", "Input Methods", "Witnessd.app")
	return os.RemoveAll(bundlePath)
}

func (p *DarwinPlatform) IsInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	bundlePath := filepath.Join(home, "Library", "Input Methods", "Witnessd.app")
	_, err = os.Stat(bundlePath)
	return err == nil
}

func (p *DarwinPlatform) IsActive() bool {
	// Would need to query the system for current input source
	// This requires calling into Cocoa/Carbon APIs
	return false
}

func (p *DarwinPlatform) Activate() error {
	// Would need to call TISSelectInputSource
	return errors.New("not implemented: use System Preferences to select input method")
}

func (p *DarwinPlatform) generateInfoPlist() string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleDisplayName</key>
    <string>` + p.config.DisplayName + `</string>
    <key>CFBundleExecutable</key>
    <string>Witnessd</string>
    <key>CFBundleIdentifier</key>
    <string>` + p.config.BundleID + `</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>Witnessd</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSBackgroundOnly</key>
    <true/>
    <key>LSMinimumSystemVersion</key>
    <string>10.15</string>
    <key>NSPrincipalClass</key>
    <string>NSApplication</string>
    <key>InputMethodConnectionName</key>
    <string>` + p.config.BundleID + `_Connection</string>
    <key>InputMethodServerControllerClass</key>
    <string>WitnessdInputController</string>
    <key>tsInputMethodCharacterRepertoireKey</key>
    <array>
        <string>Latn</string>
    </array>
    <key>tsInputMethodIconFileKey</key>
    <string>icon</string>
    <key>TISInputSourceID</key>
    <string>` + p.config.BundleID + `</string>
    <key>TISIntendedLanguage</key>
    <string>en</string>
</dict>
</plist>`
}

// DarwinZoneMapping provides macOS-specific keycode mapping.
// macOS uses virtual key codes defined in Carbon/HIToolbox/Events.h
type DarwinZoneMapping struct{}

func (DarwinZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// macOS virtual key codes (same as jitter package)
	switch keyCode {
	// Zone 0: Left pinky
	case 0x0C, 0x00, 0x06: // Q, A, Z
		return 0
	// Zone 1: Left ring
	case 0x0D, 0x01, 0x07: // W, S, X
		return 1
	// Zone 2: Left middle
	case 0x0E, 0x02, 0x08: // E, D, C
		return 2
	// Zone 3: Left index (including reach)
	case 0x0F, 0x11, 0x03, 0x05, 0x09, 0x0B: // R, T, F, G, V, B
		return 3
	// Zone 4: Right index (including reach)
	case 0x10, 0x20, 0x04, 0x26, 0x2D, 0x2E: // Y, U, H, J, N, M
		return 4
	// Zone 5: Right middle
	case 0x22, 0x28, 0x2B: // I, K, comma
		return 5
	// Zone 6: Right ring
	case 0x1F, 0x25, 0x2F: // O, L, period
		return 6
	// Zone 7: Right pinky
	case 0x23, 0x29, 0x2C: // P, semicolon, slash
		return 7
	default:
		return -1
	}
}

func (DarwinZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

// Ensure DarwinPlatform implements Platform
var _ Platform = (*DarwinPlatform)(nil)
