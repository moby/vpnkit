package libproxy

import (
	"io"
	"sync"
)

// io.Pipe is synchronous but we need to decouple the Read and Write calls
// with buffering. Adding bufio.NewWriter still requires domeone else to call
// `Flush` in a background thread to perform the write. It's simpler to create
// our own bufferedPipe out of an array of []byte

// - each direction within the connection is represented by a bufferedPipe
// - each bufferedPipe can be shutdown such that further writes return EOF
//   and reads return EOF after the buffer is exhausted

type bufferedPipe struct {
	bufs [][]byte
	eof  bool
	m    *sync.Mutex
	c    *sync.Cond
}

func newBufferedPipe() *bufferedPipe {
	var m sync.Mutex
	c := sync.NewCond(&m)
	return &bufferedPipe{
		m: &m,
		c: c,
	}
}

func (pipe *bufferedPipe) TryReadLocked(p []byte) (n int, err error) {
	// drain buffers before considering EOF
	if len(pipe.bufs) > 0 {
		first := pipe.bufs[0]
		n := copy(p, pipe.bufs[0])
		pipe.bufs[0] = first[n:]

		if len(pipe.bufs[0]) > 0 {
			// some of the first fragment remains
			return n, nil
		}
		// first fragment consumed
		pipe.bufs = pipe.bufs[1:]
		return n, nil
	}
	if pipe.eof {
		return 0, io.EOF
	}
	return 0, nil
}

func (pipe *bufferedPipe) Read(p []byte) (n int, err error) {
	pipe.m.Lock()
	defer pipe.m.Unlock()
	for {
		n, err := pipe.TryReadLocked(p)
		if n > 0 || err != nil {
			return n, err
		}
		pipe.c.Wait()
	}
}

func (pipe *bufferedPipe) Write(p []byte) (n int, err error) {
	buf := make([]byte, len(p))
	copy(buf, p)
	pipe.m.Lock()
	defer pipe.m.Unlock()
	if pipe.eof {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	pipe.bufs = append(pipe.bufs, buf)
	pipe.c.Broadcast()
	return len(p), nil
}

func (pipe *bufferedPipe) CloseWrite() error {
	pipe.m.Lock()
	defer pipe.m.Unlock()
	pipe.eof = true
	pipe.c.Broadcast()
	return nil
}

type loopback struct {
	write  *bufferedPipe
	read   *bufferedPipe
	closed bool
}

func newLoopback() *loopback {
	write := newBufferedPipe()
	read := newBufferedPipe()
	return &loopback{
		write: write,
		read:  read,
	}
}

func (l *loopback) OtherEnd() *loopback {
	return &loopback{
		write: l.read,
		read:  l.write,
	}
}

func (l *loopback) Read(p []byte) (n int, err error) {
	l.read.m.Lock()
	defer l.read.m.Unlock()
	for {
		n, err := l.read.TryReadLocked(p)
		if n > 0 || err != nil {
			return n, err
		}
		l.read.c.Wait()
	}
}

func (l *loopback) Write(p []byte) (n int, err error) {
	return l.write.Write(p)
}

func (l *loopback) CloseRead() error {
	return l.read.CloseWrite()
}

func (l *loopback) CloseWrite() error {
	return l.write.CloseWrite()
}

func (l *loopback) Close() error {
	err1 := l.CloseRead()
	err2 := l.CloseWrite()
	if err1 != nil {
		return err1
	}
	return err2
}

var _ Conn = &loopback{}
