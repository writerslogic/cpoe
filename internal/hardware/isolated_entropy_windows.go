//go:build windows
// +build windows

package hardware

import (
	"net"
	"os"
)

// getPeerCredentials gets the credentials of the connected peer on Windows.
// Windows named pipes have different security mechanisms.
func getPeerCredentials(conn net.Conn) (pid int32, uid uint32, err error) {
	// On Windows, we use named pipe security instead of SO_PEERCRED
	// The named pipe ACL restricts who can connect
	// We return placeholder values here - actual implementation would use
	// GetNamedPipeClientProcessId and GetNamedPipeClientSessionId
	return 0, 0, nil
}

// setSocketPermissions sets restrictive permissions on Windows.
func setSocketPermissions(socketPath string) error {
	// On Windows, we would use SetNamedPipeHandleState and SetSecurityInfo
	// For now, use file permissions as a basic measure
	return os.Chmod(socketPath, 0600)
}

// dropPrivilegesWindows drops privileges on Windows systems.
func dropPrivilegesWindows() error {
	// On Windows, privilege dropping is more complex:
	// 1. Create a restricted token with CreateRestrictedToken
	// 2. Use SetThreadToken or ImpersonateLoggedOnUser
	// 3. Remove unnecessary privileges with AdjustTokenPrivileges
	// This is a placeholder - full implementation requires Windows API calls
	return nil
}

// secureMemory attempts to lock memory on Windows.
func secureMemory(data []byte) error {
	// On Windows, use VirtualLock
	// This requires the SE_LOCK_MEMORY_NAME privilege
	// Placeholder - actual implementation requires Windows API calls
	return nil
}

// unsecureMemory unlocks memory on Windows.
func unsecureMemory(data []byte) error {
	// On Windows, use VirtualUnlock
	return nil
}
