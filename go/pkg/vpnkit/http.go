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
	ListPath     = "/list"
	ExposePath   = "/expose"
	UnexposePath = "/unexpose"
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
	Expose(echo.Context) error
	Unexpose(echo.Context) error
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

	e.POST(ExposePath, func(c echo.Context) error {
		return h.Expose(c)
	})
	e.POST(UnexposePath, func(c echo.Context) error {
		return h.Unexpose(c)
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
func (h *httpServer) Expose(c echo.Context) error {
	var port Port
	if err := c.Bind(&port); err != nil {
		return err
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
func (h *httpServer) Unexpose(c echo.Context) error {
	var port Port
	if err := c.Bind(&port); err != nil {
		return err
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
	res, err := h.client.Post("http://unix/expose", "application/json", &buf)
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
		return fmt.Errorf("/expose returned unexpected status: %d", res.StatusCode)
	}
	return nil
}

func (h *httpClient) Unexpose(_ context.Context, port *Port) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	if err := enc.Encode(port); err != nil {
		return err
	}
	res, err := h.client.Post("http://unix/unexpose", "application/json", &buf)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("/unexpose returned unexpected status: %d", res.StatusCode)
	}
	return nil
}

func (h *httpClient) ListExposed(context.Context) ([]Port, error) {
	res, err := h.client.Get("http://unix/list")
	if err != nil {
		fmt.Printf("GET failed with %v\n", err)
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("/list returned unexpected status: %d", res.StatusCode)
	}
	dec := json.NewDecoder(res.Body)
	var ports []Port
	if err := dec.Decode(&ports); err != nil {
		return nil, err
	}
	return ports, nil
}
