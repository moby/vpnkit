// +build !windows

package forward

import (
	"os"
	"syscall"
)

// isSaveToRemove returns true if the path references a Unix domain socket or named pipe
// or if the path doesn't exist at all
func isSafeToRemove(path string) bool {
	var statT syscall.Stat_t
	if err := syscall.Stat(path, &statT); err != nil {
		if os.IsNotExist(err) {
			return true
		}
		return false // cannot stat suggests something is wrong
	}
	return statT.Mode&syscall.S_IFMT == syscall.S_IFSOCK
}