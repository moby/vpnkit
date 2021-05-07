// +build !windows

package transport

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMaxPathLength(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-max-path-length")
	require.Nil(t, err)
	defer func() {
		assert.Nil(t, os.RemoveAll(dir))
	}()
	path := path.Join(dir, "socket")
	for {
		l, err := net.Listen("unix", path)
		if err != nil {
			if len(path) > maxUnixSocketPathLen {
				return
			}
			fmt.Printf("path length %d is <= maximum %d\n", len(path), maxUnixSocketPathLen)
			t.Fail()
			return
		}
		if len(path) > maxUnixSocketPathLen {
			fmt.Printf("path length %d is > maximum %d\n", len(path), maxUnixSocketPathLen)
			t.Fail()
		}
		require.Nil(t, l.Close())
		path = path + "1"
	}
}
