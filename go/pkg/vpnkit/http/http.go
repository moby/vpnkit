package http

import (
	"context"
	"io"

	"github.com/labstack/echo/v4"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/moby/vpnkit/go/pkg/vpnkit/transport"
)

// Server exposes port control over HTTP.
type Server interface {
	Start()
	Stop() error
	List(echo.Context) error
	ExposePort(echo.Context) error
	ExposePipe(echo.Context) error
	UnexposePort(echo.Context) error
	UnexposePipe(echo.Context) error
	DumpState(echo.Context) error

	Echo() *echo.Echo
}

// NewServer handles requests to manipulate exposed ports.
func NewServer(path string, impl vpnkit.Implementation) (Server, error) {
	t := transport.Choose(path)
	l, err := t.Listen(path)
	if err != nil {
		return nil, err
	}
	e := echo.New()
	e.HideBanner = true
	e.Listener = l
	h := &httpServer{
		e,
		impl,
	}

	e.PUT(vpnkit.ExposePortPath, func(c echo.Context) error {
		return h.ExposePort(c)
	})
	// for backwards compat
	e.POST(vpnkit.ExposePortPath, func(c echo.Context) error {
		return h.ExposePort(c)
	})
	e.PUT(vpnkit.ExposePipePath, func(c echo.Context) error {
		return h.ExposePipe(c)
	})
	// for backwards compat
	e.POST(vpnkit.ExposePipePath, func(c echo.Context) error {
		return h.ExposePipe(c)
	})
	e.DELETE(vpnkit.UnexposePortPath, func(c echo.Context) error {
		return h.UnexposePort(c)
	})
	// for backwards compat
	e.POST(vpnkit.UnexposePortPath, func(c echo.Context) error {
		return h.UnexposePort(c)
	})
	e.DELETE(vpnkit.UnexposePipePath, func(c echo.Context) error {
		return h.UnexposePipe(c)
	})
	// for backwards compat
	e.POST(vpnkit.UnexposePipePath, func(c echo.Context) error {
		return h.UnexposePipe(c)
	})
	e.GET(vpnkit.ListPath, func(c echo.Context) error {
		return h.List(c)
	})
	e.GET(vpnkit.DumpStatePath, func(c echo.Context) error {
		return h.DumpState(c)
	})

	return h, nil
}

type httpServer struct {
	e    *echo.Echo
	impl vpnkit.Implementation
}

// Echo returns the server so logging can be customised.
func (h *httpServer) Echo() *echo.Echo {
	return h.e
}

// List ports HTTP handler
func (h *httpServer) List(c echo.Context) error {
	ports, err := h.impl.ListExposed(context.Background())
	if err != nil {
		return err
	}
	return c.JSON(200, ports)
}

// Expose port HTTP handler
func (h *httpServer) ExposePort(c echo.Context) error {
	var port vpnkit.Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != vpnkit.TCP && port.Proto != vpnkit.UDP {
		return c.JSON(400, "exposed ports can only be TCP or UDP")
	}
	err := h.impl.Expose(context.Background(), &port)
	if err == nil {
		return nil
	}
	if e, ok := err.(*vpnkit.ExposeError); ok {
		return c.JSON(400, e)
	}
	return err
}

// Expose pipe HTTP handler
func (h *httpServer) ExposePipe(c echo.Context) error {
	var port vpnkit.Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != vpnkit.Unix {
		return c.JSON(400, "exposed pipes can only have proto=Unix")
	}
	err := h.impl.Expose(context.Background(), &port)
	if err == nil {
		return nil
	}
	if e, ok := err.(*vpnkit.ExposeError); ok {
		return c.JSON(400, e)
	}
	return err
}

// Unexpose port HTTP handler
func (h *httpServer) UnexposePort(c echo.Context) error {
	var port vpnkit.Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != vpnkit.TCP && port.Proto != vpnkit.UDP {
		return c.JSON(400, "exposed ports can only be TCP or UDP")
	}
	return h.impl.Unexpose(context.Background(), &port)
}

// Unexpose pipe HTTP handler
func (h *httpServer) UnexposePipe(c echo.Context) error {
	var port vpnkit.Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != vpnkit.Unix {
		return c.JSON(400, "exposed pipes can only have proto=Unix")
	}
	return h.impl.Unexpose(context.Background(), &port)
}

func (h *httpServer) DumpState(c echo.Context) error {
	r, w := io.Pipe()
	go func() {
		h.impl.DumpState(context.Background(), w)
		w.Close()
	}()
	return c.Stream(200, "text/plain", r)
}

func (h *httpServer) Start() {
	go func() {
		h.e.Start("")
	}()
}

func (h *httpServer) Stop() error {
	return h.e.Close()
}
