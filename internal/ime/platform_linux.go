//go:build linux

package ime

import (
	"errors"
	"os"
	"path/filepath"
)

// LinuxPlatform implements the Platform interface for Linux.
// Supports both IBus and Fcitx frameworks.
type LinuxPlatform struct {
	config    PlatformConfig
	engine    *Engine
	framework string // "ibus" or "fcitx"
}

// NewLinuxPlatform creates a new Linux IME platform.
func NewLinuxPlatform(config PlatformConfig, engine *Engine) *LinuxPlatform {
	framework := detectFramework()
	return &LinuxPlatform{
		config:    config,
		engine:    engine,
		framework: framework,
	}
}

// detectFramework determines which IME framework is available.
func detectFramework() string {
	// Check for IBus first (most common on GNOME)
	if _, err := os.Stat("/usr/share/ibus/component"); err == nil {
		return "ibus"
	}
	// Check for Fcitx (common on KDE)
	if _, err := os.Stat("/usr/share/fcitx/addon"); err == nil {
		return "fcitx"
	}
	return "ibus" // Default to IBus
}

func (p *LinuxPlatform) Name() string {
	return "linux"
}

func (p *LinuxPlatform) Available() bool {
	return p.framework != ""
}

func (p *LinuxPlatform) Install() error {
	switch p.framework {
	case "ibus":
		return p.installIBus()
	case "fcitx":
		return p.installFcitx()
	default:
		return errors.New("no supported IME framework found")
	}
}

func (p *LinuxPlatform) installIBus() error {
	// IBus installation requires:
	// 1. Create component XML in ~/.local/share/ibus/component/
	// 2. Create engine binary
	// 3. Restart IBus daemon

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	componentDir := filepath.Join(home, ".local", "share", "ibus", "component")
	if err := os.MkdirAll(componentDir, 0755); err != nil {
		return err
	}

	componentXML := p.generateIBusComponent()
	componentPath := filepath.Join(componentDir, "witnessd.xml")
	if err := os.WriteFile(componentPath, []byte(componentXML), 0644); err != nil {
		return err
	}

	return nil
}

func (p *LinuxPlatform) generateIBusComponent() string {
	return `<?xml version="1.0" encoding="utf-8"?>
<component>
    <name>com.witnessd.ibus</name>
    <description>Witnessd Input Method</description>
    <exec>/usr/local/bin/witnessd-ime</exec>
    <version>1.0</version>
    <author>Witnessd</author>
    <license>MIT</license>
    <homepage>https://github.com/witnessd/witnessd</homepage>
    <textdomain>witnessd</textdomain>
    <engines>
        <engine>
            <name>witnessd</name>
            <language>en</language>
            <license>MIT</license>
            <author>Witnessd</author>
            <icon>/usr/share/icons/witnessd.png</icon>
            <layout>us</layout>
            <longname>Witnessd</longname>
            <description>Cryptographic authorship witnessing keyboard</description>
            <rank>99</rank>
            <symbol>W</symbol>
        </engine>
    </engines>
</component>`
}

func (p *LinuxPlatform) installFcitx() error {
	// Fcitx5 installation (similar structure)
	return errors.New("fcitx installation not yet implemented")
}

func (p *LinuxPlatform) Uninstall() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	componentPath := filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml")
	return os.Remove(componentPath)
}

func (p *LinuxPlatform) IsInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}

	componentPath := filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml")
	_, err = os.Stat(componentPath)
	return err == nil
}

func (p *LinuxPlatform) IsActive() bool {
	// Would need to query IBus/Fcitx for current engine
	return false
}

func (p *LinuxPlatform) Activate() error {
	return errors.New("not implemented: use system settings to select input method")
}

// LinuxZoneMapping provides Linux-specific keycode mapping.
// Uses X11 keycodes (evdev).
type LinuxZoneMapping struct{}

func (LinuxZoneMapping) KeyCodeToZone(keyCode uint16) int {
	// X11/evdev keycodes (offset by 8 from raw scancodes)
	// These are the keycodes you'd get from XKeyEvent.keycode
	switch keyCode {
	// Zone 0: Left pinky - Q(24), A(38), Z(52)
	case 24, 38, 52:
		return 0
	// Zone 1: Left ring - W(25), S(39), X(53)
	case 25, 39, 53:
		return 1
	// Zone 2: Left middle - E(26), D(40), C(54)
	case 26, 40, 54:
		return 2
	// Zone 3: Left index - R(27), T(28), F(41), G(42), V(55), B(56)
	case 27, 28, 41, 42, 55, 56:
		return 3
	// Zone 4: Right index - Y(29), U(30), H(43), J(44), N(57), M(58)
	case 29, 30, 43, 44, 57, 58:
		return 4
	// Zone 5: Right middle - I(31), K(45), comma(59)
	case 31, 45, 59:
		return 5
	// Zone 6: Right ring - O(32), L(46), period(60)
	case 32, 46, 60:
		return 6
	// Zone 7: Right pinky - P(33), semicolon(47), slash(61)
	case 33, 47, 61:
		return 7
	default:
		return -1
	}
}

func (LinuxZoneMapping) CharToZone(char rune) int {
	return zoneFromChar(char)
}

var _ Platform = (*LinuxPlatform)(nil)
