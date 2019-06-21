package forward

import (
	"strings"
)


// isSaveToRemove returns true if the path references a Unix domain socket or named pipe
// or if the path doesn't exist at all
func isSafeToRemove(path string) bool {
	return strings.HasPrefix(`\\.\pipe\`, path)
}