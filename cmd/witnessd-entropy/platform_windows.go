//go:build windows
// +build windows

package main

import (
	"crypto/rand"
	"log"
)

// dropPrivileges on Windows is a no-op (handled differently via tokens).
func dropPrivileges(uid, gid int) error {
	// Windows privilege dropping requires CreateRestrictedToken and AdjustTokenPrivileges
	// This is a placeholder - full implementation requires Windows API calls
	return nil
}

// lockMemory attempts to lock memory on Windows.
func lockMemory() {
	// Windows uses VirtualLock which requires SE_LOCK_MEMORY_NAME privilege
	// This is a placeholder - full implementation requires Windows API calls
	log.Printf("Warning: memory locking not implemented on Windows")
}

// readFromDevRandom reads entropy using Windows CryptGenRandom.
func readFromDevRandom(p []byte) (int, error) {
	// On Windows, use the crypto/rand package which uses CryptGenRandom
	return rand.Read(p)
}
