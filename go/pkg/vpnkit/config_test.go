package vpnkit

import (
	"bytes"
	"fmt"
	"testing"
)

func TestGatewayForwards(t *testing.T) {
	forwards := GatewayForwards([]Forward{
		{
			Protocol:     TCP,
			ExternalPort: 53,
			InternalIP:   "127.0.0.1",
			InternalPort: 5353,
		},
		{
			Protocol:     UDP,
			ExternalPort: 53,
			InternalIP:   "127.0.0.1",
			InternalPort: 5353,
		},
	})
	var b bytes.Buffer
	if err := forwards.Write(&b); err != nil {
		t.Fatal(err)
	}
	expected := `[{"protocol":"tcp","external_port":53,"internal_ip":"127.0.0.1","internal_port":5353},{"protocol":"udp","external_port":53,"internal_ip":"127.0.0.1","internal_port":5353}]
`

	assertEqual(t, expected, b.String(), "gateway forwards not marshalled as expected")
}

func assertEqual(t *testing.T, a interface{}, b interface{}, message string) {
	if a == b {
		return
	}
	if len(message) == 0 {
		message = fmt.Sprintf("%v != %v", a, b)
	}
	t.Fatal(message)
}
