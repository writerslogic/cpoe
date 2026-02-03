//go:build darwin
// +build darwin

package hardware

import (
	"net"
	"os"
	"syscall"
	"unsafe"
)

// LOCAL_PEERCRED is the option for getting peer credentials on Darwin.
// See sys/un.h for definition.
const LOCAL_PEERCRED = 0x001

// Xucred represents peer credentials on Darwin.
// See sys/ucred.h for the structure definition.
type xucred struct {
	Version uint32
	UID     uint32
	Ngroups int16
	_       [2]byte // padding
	Groups  [16]uint32
}

// getPeerCredentials gets the credentials of the connected peer on Darwin using LOCAL_PEERCRED.
func getPeerCredentials(conn net.Conn) (pid int32, uid uint32, err error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, ErrProtocolViolation
	}

	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return 0, 0, err
	}

	var xuc xucred
	var credErr error

	err = rawConn.Control(func(fd uintptr) {
		credLen := uint32(unsafe.Sizeof(xuc))
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			0, // SOL_LOCAL = 0 on Darwin
			LOCAL_PEERCRED,
			uintptr(unsafe.Pointer(&xuc)),
			uintptr(unsafe.Pointer(&credLen)),
			0,
		)
		if errno != 0 {
			credErr = errno
		}
	})

	if err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}

	// Darwin doesn't provide PID via LOCAL_PEERCRED, only UID
	// We return 0 for PID and use UID for session management
	return 0, xuc.UID, nil
}

// setSocketPermissions sets restrictive permissions on the Unix socket.
func setSocketPermissions(socketPath string) error {
	return os.Chmod(socketPath, 0600)
}

// secureMemory attempts to lock memory to prevent swapping of sensitive data.
func secureMemory(data []byte) error {
	return syscall.Mlock(data)
}

// unsecureMemory unlocks previously locked memory.
func unsecureMemory(data []byte) error {
	return syscall.Munlock(data)
}
