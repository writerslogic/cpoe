// Package watcher monitors files for changes and triggers witness events.
package watcher

import (
	"crypto/sha256"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Event represents a file that has been witnessed.
type Event struct {
	Path      string
	Hash      [32]byte
	Size      int64
	Timestamp time.Time
}

// Watcher monitors files and directories for changes.
type Watcher struct {
	fsWatcher *fsnotify.Watcher
	paths     []string
	interval  time.Duration

	// State tracking: path -> last modification time
	state   map[string]time.Time
	stateMu sync.RWMutex

	// Event channel
	events chan Event
	errors chan error

	// Control
	done chan struct{}
	wg   sync.WaitGroup
}

// New creates a new file watcher.
func New(paths []string, intervalSec int) (*Watcher, error) {
	fsWatcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{
		fsWatcher: fsWatcher,
		paths:     paths,
		interval:  time.Duration(intervalSec) * time.Second,
		state:     make(map[string]time.Time),
		events:    make(chan Event, 100),
		errors:    make(chan error, 10),
		done:      make(chan struct{}),
	}

	return w, nil
}

// Events returns the channel of witness events.
func (w *Watcher) Events() <-chan Event {
	return w.events
}

// Errors returns the channel of errors.
func (w *Watcher) Errors() <-chan error {
	return w.errors
}

// Start begins watching all configured paths.
func (w *Watcher) Start() error {
	// Add all watch paths
	for _, path := range w.paths {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return err
		}

		// Check if path exists
		info, err := os.Stat(absPath)
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Watch directory and its immediate files
			if err := w.fsWatcher.Add(absPath); err != nil {
				return err
			}

			// Scan existing files
			entries, err := os.ReadDir(absPath)
			if err != nil {
				return err
			}

			for _, entry := range entries {
				if !entry.IsDir() {
					filePath := filepath.Join(absPath, entry.Name())
					w.trackFile(filePath)
				}
			}
		} else {
			// Watch single file (by watching its directory)
			dir := filepath.Dir(absPath)
			if err := w.fsWatcher.Add(dir); err != nil {
				return err
			}
			w.trackFile(absPath)
		}
	}

	// Start the event loop
	w.wg.Add(2)
	go w.eventLoop()
	go w.debounceLoop()

	return nil
}

// Stop gracefully shuts down the watcher.
func (w *Watcher) Stop() error {
	close(w.done)
	w.wg.Wait()
	close(w.events)
	close(w.errors)
	return w.fsWatcher.Close()
}

// trackFile adds a file to state tracking.
func (w *Watcher) trackFile(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	w.stateMu.Lock()
	w.state[path] = info.ModTime()
	w.stateMu.Unlock()
}

// eventLoop handles fsnotify events.
func (w *Watcher) eventLoop() {
	defer w.wg.Done()

	for {
		select {
		case <-w.done:
			return

		case event, ok := <-w.fsWatcher.Events:
			if !ok {
				return
			}

			// Only track writes and creates
			if event.Op&(fsnotify.Write|fsnotify.Create) == 0 {
				continue
			}

			// Skip directories
			info, err := os.Stat(event.Name)
			if err != nil || info.IsDir() {
				continue
			}

			// Update modification time
			w.stateMu.Lock()
			w.state[event.Name] = time.Now()
			w.stateMu.Unlock()

		case err, ok := <-w.fsWatcher.Errors:
			if !ok {
				return
			}
			select {
			case w.errors <- err:
			default:
			}
		}
	}
}

// debounceLoop checks for stable files and triggers witness events.
func (w *Watcher) debounceLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.done:
			return

		case now := <-ticker.C:
			w.checkStableFiles(now)
		}
	}
}

// checkStableFiles finds files that haven't changed for the debounce interval.
func (w *Watcher) checkStableFiles(now time.Time) {
	w.stateMu.Lock()
	defer w.stateMu.Unlock()

	threshold := now.Add(-w.interval)

	for path, lastMod := range w.state {
		if lastMod.Before(threshold) {
			// File has been stable long enough - witness it
			hash, size, err := HashFile(path)
			if err != nil {
				select {
				case w.errors <- err:
				default:
				}
				continue
			}

			event := Event{
				Path:      path,
				Hash:      hash,
				Size:      size,
				Timestamp: now,
			}

			select {
			case w.events <- event:
				// Update state to current time to prevent re-witnessing
				// until next modification
				delete(w.state, path)
			default:
				// Event channel full, try again later
			}
		}
	}
}

// HashFile computes SHA-256 hash of a file using streaming.
// This handles large files efficiently without loading into memory.
func HashFile(path string) ([32]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return [32]byte{}, 0, err
	}
	defer f.Close()

	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return [32]byte{}, 0, err
	}

	var hash [32]byte
	copy(hash[:], h.Sum(nil))
	return hash, size, nil
}

// WatchedPaths returns the list of paths being watched.
func (w *Watcher) WatchedPaths() []string {
	return w.paths
}

// TrackedFiles returns the current number of tracked files.
func (w *Watcher) TrackedFiles() int {
	w.stateMu.RLock()
	defer w.stateMu.RUnlock()
	return len(w.state)
}
