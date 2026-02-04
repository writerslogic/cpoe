//go:build darwin || linux
// +build darwin linux

package main

import (
	"fmt"
	"log"
	"os"
	"syscall"
)

// dropPrivileges drops root privileges on Unix systems.
func dropPrivileges(uid, gid int) error {
	// Set supplementary groups to empty
	if err := syscall.Setgroups([]int{}); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}

	// Set GID first (must be done before UID)
	if err := syscall.Setgid(gid); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}

	// Set UID last
	if err := syscall.Setuid(uid); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}

	// Verify we can't regain privileges
	if os.Getuid() == 0 || os.Geteuid() == 0 {
		return fmt.Errorf("failed to drop privileges")
	}

	return nil
}

// lockMemory attempts to lock all current and future memory.
func lockMemory() {
	// MCL_CURRENT = 1, MCL_FUTURE = 2
	if err := syscall.Mlockall(1 | 2); err != nil {
		// Non-fatal - may require elevated privileges
		log.Printf("Warning: could not lock memory: %v", err)
	}
}

// readFromDevRandom reads entropy from /dev/random.
func readFromDevRandom(p []byte) (int, error) {
	f, err := os.Open("/dev/random")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Read(p)
}
