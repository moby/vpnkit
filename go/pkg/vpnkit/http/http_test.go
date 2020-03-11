package http

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/stretchr/testify/assert"
)

type mockImpl struct {
	exposed     []vpnkit.Port
	exposeError *vpnkit.ExposeError
}

func (m *mockImpl) Expose(_ context.Context, p *vpnkit.Port) error {
	if p == nil {
		return errors.New("cannot expose a nil port")
	}
	if m.exposeError != nil {
		return m.exposeError
	}
	m.exposed = append(m.exposed, *p)
	return nil
}

func (m *mockImpl) Unexpose(_ context.Context, p *vpnkit.Port) error {
	if p == nil {
		return errors.New("cannot unexpose a nil port")
	}
	var exposed []vpnkit.Port
	for _, port := range m.exposed {
		if port.String() == p.String() {
			continue
		}
		exposed = append(exposed, port)
	}
	m.exposed = exposed
	return nil
}

func (m *mockImpl) ListExposed(_ context.Context) ([]vpnkit.Port, error) {
	return m.exposed, nil
}

func (m *mockImpl) DumpState(_ context.Context, _ io.Writer) error {
	return nil
}

func TestEmptyList(t *testing.T) {
	impl := &mockImpl{}
	path := testPath()
	s, err := NewServer(path, impl)
	assert.Nil(t, err)
	assert.NotNil(t, s)
	s.Start()
	defer s.Stop()
	c, err := vpnkit.NewClient(path)
	assert.Nil(t, err)
	ctx := context.Background()
	ports, err := c.ListExposed(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(ports))
}

func TestNonEmpyList(t *testing.T) {
	impl := &mockImpl{}
	path := testPath()
	s, err := NewServer(path, impl)
	assert.Nil(t, err)
	assert.NotNil(t, s)
	s.Start()
	defer s.Stop()
	c, err := vpnkit.NewClient(path)
	assert.Nil(t, err)
	ctx := context.Background()
	assert.Nil(t, c.Expose(ctx, &vpnkit.Port{
		Proto:   vpnkit.TCP,
		InPort:  1,
		OutPort: 1,
	}))
	assert.Nil(t, c.Expose(ctx, &vpnkit.Port{
		Proto:   vpnkit.UDP,
		InPort:  2,
		OutPort: 2,
	}))
	ports, err := c.ListExposed(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(ports))
}

func TestUnexpose(t *testing.T) {
	impl := &mockImpl{}
	path := testPath()
	s, err := NewServer(path, impl)
	assert.Nil(t, err)
	assert.NotNil(t, s)
	s.Start()
	defer s.Stop()
	c, err := vpnkit.NewClient(path)
	assert.Nil(t, err)
	ctx := context.Background()
	p := &vpnkit.Port{
		Proto:   vpnkit.TCP,
		InPort:  1,
		OutPort: 1,
	}
	assert.Nil(t, c.Expose(ctx, p))
	q := &vpnkit.Port{
		Proto:   vpnkit.UDP,
		InPort:  2,
		OutPort: 2,
	}
	assert.Nil(t, c.Expose(ctx, q))
	assert.Nil(t, c.Unexpose(ctx, p))
	ports, err := c.ListExposed(ctx)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(ports))
	assert.Equal(t, q.String(), ports[0].String())
}

func TestExposeError(t *testing.T) {
	impl := &mockImpl{}
	path := testPath()
	s, err := NewServer(path, impl)
	assert.Nil(t, err)
	assert.NotNil(t, s)
	s.Start()
	defer s.Stop()
	c, err := vpnkit.NewClient(path)
	assert.Nil(t, err)
	impl.exposeError = &vpnkit.ExposeError{
		Message: "EADDRESSINUSE",
	}
	ctx := context.Background()
	err = c.Expose(ctx, &vpnkit.Port{
		Proto:   vpnkit.TCP,
		InPort:  1,
		OutPort: 1,
	})
	assert.Equal(t, impl.exposeError, err)
}

func testPath() string {
	if runtime.GOOS == "windows" {
		return `\\.\pipe\vpnkitTestPipe`
	}
	return filepath.Join(os.TempDir(), "http-test")
}
