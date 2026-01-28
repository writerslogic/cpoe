//go:build linux

// witnessd-ibus is the Linux IBus Input Method Engine.
//
// This connects to the IBus daemon via D-Bus and handles key events,
// routing them through the witnessd engine for cryptographic witnessing.
//
// Installation:
//  1. Copy binary to /usr/local/bin/witnessd-ibus
//  2. Copy witnessd.xml to ~/.local/share/ibus/component/
//  3. Restart IBus: ibus restart
//  4. Enable via: ibus-setup or GNOME Settings > Keyboard > Input Sources
//
// The engine runs in pass-through mode - it observes and records
// typing patterns but forwards all input unchanged to applications.
package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/godbus/dbus/v5"

	"witnessd/internal/ime"
)

const (
	ibusService   = "org.freedesktop.IBus"
	ibusPath      = "/org/freedesktop/IBus"
	ibusInterface = "org.freedesktop.IBus"

	engineInterface = "org.freedesktop.IBus.Engine"
	enginePath      = "/org/freedesktop/IBus/Engine"

	witnessdBusName = "com.witnessd.IBus"
)

var (
	engine   *ime.Engine
	engineMu sync.Mutex
	conn     *dbus.Conn
	logFile  *os.File
)

func main() {
	installFlag := flag.Bool("install", false, "Install IBus component")
	uninstallFlag := flag.Bool("uninstall", false, "Uninstall IBus component")
	flag.Parse()

	if *installFlag {
		if err := installComponent(); err != nil {
			log.Fatalf("Failed to install: %v", err)
		}
		log.Println("Installed successfully. Run 'ibus restart' to load.")
		return
	}

	if *uninstallFlag {
		if err := uninstallComponent(); err != nil {
			log.Fatalf("Failed to uninstall: %v", err)
		}
		log.Println("Uninstalled successfully.")
		return
	}

	// Initialize logging
	if err := initLogging(); err != nil {
		log.Printf("Warning: could not initialize logging: %v", err)
	}

	// Initialize engine
	engine = ime.NewEngine()

	// Connect to session bus
	var err error
	conn, err = dbus.SessionBus()
	if err != nil {
		log.Fatalf("Failed to connect to session bus: %v", err)
	}
	defer conn.Close()

	// Request our bus name
	reply, err := conn.RequestName(witnessdBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("Failed to request bus name: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("Bus name already taken")
	}

	// Export our engine object
	eng := &IBusEngine{}
	conn.Export(eng, enginePath, engineInterface)

	log.Println("Witnessd IBus engine started")

	// Handle shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	log.Println("Shutting down")

	// End any active session
	engineMu.Lock()
	if engine.HasActiveSession() {
		evidence, _ := engine.EndSession()
		if evidence != nil {
			log.Printf("Session ended: %d keystrokes", evidence.TotalKeystrokes)
		}
	}
	engineMu.Unlock()

	if logFile != nil {
		logFile.Close()
	}
}

func initLogging() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	logDir := filepath.Join(home, ".witnessd", "logs")
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}

	logFile, err = os.OpenFile(
		filepath.Join(logDir, "ibus.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return err
	}

	log.SetOutput(logFile)
	return nil
}

// IBusEngine implements the IBus Engine D-Bus interface.
type IBusEngine struct {
	currentApp string
	currentDoc string
}

// ProcessKeyEvent handles key press/release events.
// Returns true if the key was handled, false to pass through.
func (e *IBusEngine) ProcessKeyEvent(keyval, keycode, state uint32) (bool, *dbus.Error) {
	// Only process key press, not release
	isRelease := (state & (1 << 30)) != 0
	if isRelease {
		return false, nil
	}

	engineMu.Lock()
	defer engineMu.Unlock()

	// Start session if needed
	if !engine.HasActiveSession() {
		app := e.currentApp
		if app == "" {
			app = "unknown"
		}
		doc := e.currentDoc
		if doc == "" {
			doc = "default"
		}
		if err := engine.StartSession(ime.SessionOptions{
			AppID: app,
			DocID: doc,
		}); err != nil {
			log.Printf("Failed to start session: %v", err)
			return false, nil
		}
	}

	// Handle backspace
	if keyval == 0xff08 { // GDK_KEY_BackSpace
		if err := engine.OnTextDelete(1); err != nil {
			log.Printf("OnTextDelete error: %v", err)
		}
		return false, nil // Let IBus handle the actual delete
	}

	// Handle Delete key
	if keyval == 0xffff { // GDK_KEY_Delete
		if err := engine.OnTextDelete(1); err != nil {
			log.Printf("OnTextDelete error: %v", err)
		}
		return false, nil
	}

	// Get the character from keyval
	char := keyvalToRune(keyval)
	if char == 0 {
		return false, nil // Non-character key
	}

	// Create key with X11 keycode (add 8 for evdev offset)
	key := ime.NewKeyWithCode(uint16(keycode+8), char)

	delay, err := engine.OnKeyDown(key)
	if err != nil {
		log.Printf("OnKeyDown error: %v", err)
		return false, nil
	}

	// Record the text commit
	if err := engine.OnTextCommit(string(char)); err != nil {
		log.Printf("OnTextCommit error: %v", err)
	}

	// Note: In pass-through mode, we don't apply the jitter delay
	// as it would require async handling. The delay is recorded
	// for verification purposes.
	_ = delay

	return false, nil // Pass through to application
}

// FocusIn is called when the engine gains focus.
func (e *IBusEngine) FocusIn() *dbus.Error {
	log.Println("FocusIn")
	return nil
}

// FocusOut is called when the engine loses focus.
func (e *IBusEngine) FocusOut() *dbus.Error {
	log.Println("FocusOut")

	// End session on focus out
	engineMu.Lock()
	defer engineMu.Unlock()

	if engine.HasActiveSession() {
		evidence, err := engine.EndSession()
		if err != nil {
			log.Printf("EndSession error: %v", err)
		} else if evidence != nil {
			saveEvidence(evidence)
		}
	}

	return nil
}

// SetContentType informs about the type of content being edited.
func (e *IBusEngine) SetContentType(purpose, hints uint32) *dbus.Error {
	log.Printf("SetContentType: purpose=%d hints=%d", purpose, hints)
	return nil
}

// SetSurroundingText provides context around the cursor.
func (e *IBusEngine) SetSurroundingText(text string, cursorPos, anchorPos uint32) *dbus.Error {
	// Could use this for more context about the document
	return nil
}

// Reset resets the engine state.
func (e *IBusEngine) Reset() *dbus.Error {
	log.Println("Reset")
	return nil
}

// Enable is called when the engine is enabled.
func (e *IBusEngine) Enable() *dbus.Error {
	log.Println("Enable")
	return nil
}

// Disable is called when the engine is disabled.
func (e *IBusEngine) Disable() *dbus.Error {
	log.Println("Disable")
	return nil
}

// keyvalToRune converts X11 keysym to Unicode rune.
func keyvalToRune(keyval uint32) rune {
	// Direct Unicode mapping for Latin-1 range
	if keyval >= 0x20 && keyval <= 0x7e {
		return rune(keyval)
	}

	// Extended Latin (ISO 8859-1)
	if keyval >= 0xa0 && keyval <= 0xff {
		return rune(keyval)
	}

	// Unicode keysyms (0x01000000 + codepoint)
	if keyval >= 0x01000000 {
		return rune(keyval - 0x01000000)
	}

	return 0
}

func saveEvidence(evidence *ime.Evidence) {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Printf("Failed to get home dir: %v", err)
		return
	}

	evidenceDir := filepath.Join(home, ".witnessd", "evidence")
	if err := os.MkdirAll(evidenceDir, 0700); err != nil {
		log.Printf("Failed to create evidence dir: %v", err)
		return
	}

	jsonData, err := json.Marshal(evidence)
	if err != nil {
		log.Printf("Failed to marshal evidence: %v", err)
		return
	}

	filename := filepath.Join(evidenceDir, evidence.SessionID+".json")
	if err := os.WriteFile(filename, jsonData, 0600); err != nil {
		log.Printf("Failed to write evidence: %v", err)
		return
	}

	log.Printf("Saved evidence to %s", filename)
}

func installComponent() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	componentDir := filepath.Join(home, ".local", "share", "ibus", "component")
	if err := os.MkdirAll(componentDir, 0755); err != nil {
		return err
	}

	// Find the binary path
	binPath, err := os.Executable()
	if err != nil {
		binPath = "/usr/local/bin/witnessd-ibus"
	}

	componentXML := `<?xml version="1.0" encoding="utf-8"?>
<component>
    <name>com.witnessd.ibus</name>
    <description>Witnessd Cryptographic Authorship Witnessing</description>
    <exec>` + binPath + `</exec>
    <version>1.0.0</version>
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
            <icon>witnessd</icon>
            <layout>us</layout>
            <longname>Witnessd</longname>
            <description>Cryptographic authorship witnessing keyboard</description>
            <rank>99</rank>
            <symbol>W</symbol>
        </engine>
    </engines>
</component>`

	componentPath := filepath.Join(componentDir, "witnessd.xml")
	return os.WriteFile(componentPath, []byte(componentXML), 0644)
}

func uninstallComponent() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	componentPath := filepath.Join(home, ".local", "share", "ibus", "component", "witnessd.xml")
	return os.Remove(componentPath)
}
