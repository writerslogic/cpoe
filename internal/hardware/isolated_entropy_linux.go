//go:build linux
// +build linux

package hardware

import (
	"net"
	"os"
	"syscall"
)

// getPeerCredentials gets the credentials of the connected peer on Linux using SO_PEERCRED.
func getPeerCredentials(conn net.Conn) (pid int32, uid uint32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, ErrProtocolViolation
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var cred *syscall.Ucred
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})

	if err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}

	return cred.Pid, cred.Uid, nil
}

// setSocketPermissions sets restrictive permissions on the Unix socket.
func setSocketPermissions(socketPath string) error {
	return os.Chmod(socketPath, 0600)
}

// dropPrivileges drops privileges on Linux systems.
func dropPrivilegesLinux(uid, gid int) error {
	// Set resource limits
	var rLimit syscall.Rlimit
	rLimit.Max = 0
	rLimit.Cur = 0

	// Disable core dumps to prevent entropy leakage
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &rLimit); err != nil {
		// Non-fatal, continue
	}

	// If running as root, drop to specified uid/gid
	if os.Getuid() == 0 && uid > 0 {
		if err := syscall.Setgid(gid); err != nil {
			return err
		}
		if err := syscall.Setuid(uid); err != nil {
			return err
		}
	}

	return nil
}

// secureMemory attempts to lock memory to prevent swapping of sensitive data.
func secureMemory(data []byte) error {
	return syscall.Mlock(data)
}

// unsecureMemory unlocks previously locked memory.
func unsecureMemory(data []byte) error {
	return syscall.Munlock(data)
}
