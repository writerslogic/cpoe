// witnessd is the background daemon that silently witnesses document changes.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"witnessd/internal/config"
	"witnessd/internal/mmr"
	"witnessd/internal/signer"
	"witnessd/internal/watcher"
)

var (
	configPath = flag.String("config", "", "path to config file")
	verbose    = flag.Bool("v", false, "verbose logging")
)

func main() {
	flag.Parse()

	// Load configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	// Ensure directories exist
	if err := cfg.EnsureDirectories(); err != nil {
		log.Fatalf("Failed to create directories: %v", err)
	}

	// Set up logging
	logFile, err := os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", log.LstdFlags|log.Lshortfile)
	if *verbose {
		// Also log to stderr
		logger = log.New(os.Stderr, "[witnessd] ", log.LstdFlags|log.Lshortfile)
	}

	logger.Printf("Starting witnessd...")

	// Check signing key exists
	if _, err := os.Stat(cfg.SigningKeyPath); os.IsNotExist(err) {
		logger.Fatalf("Signing key not found: %s", cfg.SigningKeyPath)
	}

	// Initialize MMR store
	store, err := mmr.OpenFileStore(cfg.DatabasePath)
	if err != nil {
		logger.Fatalf("Failed to open MMR store: %v", err)
	}

	mmrTree, err := mmr.New(store)
	if err != nil {
		store.Close()
		logger.Fatalf("Failed to initialize MMR: %v", err)
	}

	logger.Printf("MMR initialized with %d nodes (%d leaves)", mmrTree.Size(), mmrTree.LeafCount())

	// Initialize watcher
	if len(cfg.WatchPaths) == 0 {
		logger.Printf("Warning: no watch paths configured")
	}

	w, err := watcher.New(cfg.WatchPaths, cfg.Interval)
	if err != nil {
		store.Close()
		logger.Fatalf("Failed to create watcher: %v", err)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start watching
	if err := w.Start(); err != nil {
		store.Close()
		logger.Fatalf("Failed to start watcher: %v", err)
	}

	logger.Printf("Watching %d paths with %d second debounce", len(cfg.WatchPaths), cfg.Interval)

	// Write PID file
	pidPath := filepath.Join(config.WitnessdDir(), "witnessd.pid")
	if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
		logger.Printf("Warning: failed to write PID file: %v", err)
	}
	defer os.Remove(pidPath)

	// Main event loop
	eventCount := uint64(0)
	running := true

	for running {
		select {
		case event := <-w.Events():
			// Witness the file
			idx, err := mmrTree.Append(event.Hash[:])
			if err != nil {
				logger.Printf("Error appending to MMR: %v", err)
				continue
			}

			eventCount++
			logger.Printf("Witnessed: %s (index=%d, hash=%s)",
				event.Path, idx, hex.EncodeToString(event.Hash[:8]))

			// Get and sign the root periodically (every 10 events or on shutdown)
			if eventCount%10 == 0 {
				if err := signAndLogRoot(cfg, mmrTree, logger); err != nil {
					logger.Printf("Warning: failed to sign root: %v", err)
				}
			}

		case err := <-w.Errors():
			logger.Printf("Watcher error: %v", err)

		case sig := <-sigChan:
			logger.Printf("Received signal %v, shutting down...", sig)
			running = false
		}
	}

	// Graceful shutdown
	logger.Printf("Stopping watcher...")
	if err := w.Stop(); err != nil {
		logger.Printf("Error stopping watcher: %v", err)
	}

	// Final root signing
	if eventCount > 0 {
		logger.Printf("Signing final root...")
		if err := signAndLogRoot(cfg, mmrTree, logger); err != nil {
			logger.Printf("Warning: failed to sign final root: %v", err)
		}
	}

	// Sync and close MMR store
	logger.Printf("Syncing MMR store...")
	if err := store.Sync(); err != nil {
		logger.Printf("Error syncing store: %v", err)
	}
	if err := store.Close(); err != nil {
		logger.Printf("Error closing store: %v", err)
	}

	logger.Printf("Shutdown complete. Witnessed %d events.", eventCount)
}

// signAndLogRoot signs the current MMR root and logs it.
func signAndLogRoot(cfg *config.Config, m *mmr.MMR, logger *log.Logger) error {
	root, err := m.GetRoot()
	if err != nil {
		return fmt.Errorf("get root: %w", err)
	}

	// Load signing key
	privKey, err := signer.LoadPrivateKey(cfg.SigningKeyPath)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	// Sign the root
	sig := signer.SignCommitment(privKey, root[:])

	// Log to signatures file
	f, err := os.OpenFile(cfg.SignaturesPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("open sigs file: %w", err)
	}
	defer f.Close()

	entry := fmt.Sprintf("%s %s %s %d\n",
		time.Now().UTC().Format(time.RFC3339),
		hex.EncodeToString(root[:]),
		hex.EncodeToString(sig),
		m.Size())

	if _, err := f.WriteString(entry); err != nil {
		return fmt.Errorf("write sig: %w", err)
	}

	logger.Printf("Signed root: %s (size=%d)", hex.EncodeToString(root[:8]), m.Size())
	return nil
}
