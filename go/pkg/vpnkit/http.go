package vpnkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/moby/vpnkit/go/pkg/vpnkit/transport"
)

const (
	ListPath         = "/forwards/list"
	ExposePortPath   = "/forwards/expose/port"
	ExposePipePath   = "/forwards/expose/pipe"
	UnexposePortPath = "/forwards/unexpose/port"
	UnexposePipePath = "/forwards/unexpose/pipe"
)

// NewClient can be used to manipulated exposed ports.
func NewClient(t transport.Transport, path string) (Client, error) {
	return &httpClient{
		client: http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
					return t.Dial(c, path)
				},
			},
		},
	}, nil
}

// Server exposes port control over HTTP.
type Server interface {
	Start()
	Stop() error
	List(echo.Context) error
	ExposePort(echo.Context) error
	ExposePipe(echo.Context) error
	UnexposePort(echo.Context) error
	UnexposePipe(echo.Context) error
}

// Implementation of the control interface.
type Implementation interface {
	Client
}

// ExposeError should be reported through to the user
type ExposeError struct {
	Message string `json:"message"`
}

func (e *ExposeError) Error() string {
	return e.Message
}

// NewServer handles requests to manipulate exposed ports.
func NewServer(path string, t transport.Transport, impl Implementation) (Server, error) {
	l, err := t.Listen(path)
	if err != nil {
		return nil, err
	}
	e := echo.New()
	e.HideBanner = true
	e.Listener = l
	e.Use(middleware.Logger())
	h := &httpServer{
		e,
		impl,
	}

	e.POST(ExposePortPath, func(c echo.Context) error {
		return h.ExposePort(c)
	})
	e.POST(ExposePipePath, func(c echo.Context) error {
		return h.ExposePipe(c)
	})
	e.POST(UnexposePortPath, func(c echo.Context) error {
		return h.UnexposePort(c)
	})
	e.POST(UnexposePipePath, func(c echo.Context) error {
		return h.UnexposePipe(c)
	})
	e.GET(ListPath, func(c echo.Context) error {
		return h.List(c)
	})

	return h, nil
}

type httpServer struct {
	e    *echo.Echo
	impl Implementation
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
	var port Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != TCP && port.Proto != UDP {
		return c.JSON(400, "exposed ports can only be TCP or UDP")
	}
	err := h.impl.Expose(context.Background(), &port)
	if err == nil {
		return nil
	}
	if e, ok := err.(*ExposeError); ok {
		return c.JSON(400, e)
	}
	return err
}

// Expose pipe HTTP handler
func (h *httpServer) ExposePipe(c echo.Context) error {
	var port Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != Unix {
		return c.JSON(400, "exposed pipes can only have proto=Unix")
	}
	err := h.impl.Expose(context.Background(), &port)
	if err == nil {
		return nil
	}
	if e, ok := err.(*ExposeError); ok {
		return c.JSON(400, e)
	}
	return err
}

// Unexpose port HTTP handler
func (h *httpServer) UnexposePort(c echo.Context) error {
	var port Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != TCP && port.Proto != UDP {
		return c.JSON(400, "exposed ports can only be TCP or UDP")
	}
	return h.impl.Unexpose(context.Background(), &port)
}

// Unexpose pipe HTTP handler
func (h *httpServer) UnexposePipe(c echo.Context) error {
	var port Port
	if err := c.Bind(&port); err != nil {
		return err
	}
	if port.Proto != Unix {
		return c.JSON(400, "exposed pipes can only have proto=Unix")
	}
	return h.impl.Unexpose(context.Background(), &port)
}

func (h *httpServer) Start() {
	go func() {
		h.e.Start("")
	}()
}

func (h *httpServer) Stop() error {
	return h.e.Close()
}

const httpTimeout = 120 * time.Second

type httpClient struct {
	client http.Client
}

func (h *httpClient) Expose(_ context.Context, port *Port) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(port); err != nil {
		return err
	}
	path := ExposePortPath
	if port.Proto == Unix {
		path = ExposePipePath
	}
	res, err := h.client.Post("http://unix"+path, "application/json", &buf)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode == 400 {
		var exposeError ExposeError
		dec := json.NewDecoder(res.Body)
		if err := dec.Decode(&exposeError); err != nil {
			fmt.Printf("failed to decode: %v\n", err)
			return err
		}
		return &exposeError
	}
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf(path+" returned unexpected status: %d", res.StatusCode)
	}
	return nil
}

func (h *httpClient) Unexpose(_ context.Context, port *Port) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(port); err != nil {
		return err
	}
	path := UnexposePortPath
	if port.Proto == Unix {
		path = UnexposePipePath
	}
	res, err := h.client.Post("http://unix"+path, "application/json", &buf)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf(path+" returned unexpected status: %d", res.StatusCode)
	}
	return nil
}

func (h *httpClient) ListExposed(context.Context) ([]Port, error) {
	res, err := h.client.Get("http://unix" + ListPath)
	if err != nil {
		fmt.Printf("GET failed with %v\n", err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(ListPath+" returned unexpected status: %d", res.StatusCode)
	}
	dec := json.NewDecoder(res.Body)
	var ports []Port
	if err := dec.Decode(&ports); err != nil {
		return nil, err
	}
	return ports, nil
}
