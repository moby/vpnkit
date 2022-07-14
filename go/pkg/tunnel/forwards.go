package tunnel

import (
	"encoding/json"
	"net"

	"github.com/pkg/errors"
)

// Forward traffic for the given IP destination to the tunnel server on the Unix domain socket path.
type Forward struct {
	Protocol  Protocol   // Protocol to be forwarded.
	DstPrefix *net.IPNet // Traffic matching this network prefix will be sent via the tunnel.
	DstPort   int        // Traffic with this destination port will be sent via the tunnel.
	Path      string     // Path of the tunnel server.
}

const EveryPort = 0 // EveryPort should be sent through the tunnel

// UnmarshalForwards returns a parsed forwards specification.
func UnmarshalForwards(b []byte) ([]Forward, error) {
	var raw []forward
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, errors.Wrap(err, "unmarshalling forwards")
	}
	var results []Forward
	for _, f := range raw {
		protocol, err := readProtocol(f.Protocol)
		if err != nil {
			return nil, err
		}
		_, net, err := net.ParseCIDR(f.DstPrefix)
		if err != nil {
			return nil, errors.Wrapf(err, "parsing IP network %s", f.DstPrefix)
		}
		results = append(results, Forward{
			Protocol:  protocol,
			DstPrefix: net,
			DstPort:   f.DstPort,
			Path:      f.Path,
		})
	}
	return results, nil
}

// MarshalForwards returns a forwards specification in json format.
func MarshalForwards(all []Forward) ([]byte, error) {
	var raw []forward
	for _, f := range all {
		raw = append(raw, forward{
			Protocol:  string(f.Protocol),
			DstPrefix: f.DstPrefix.String(),
			DstPort:   f.DstPort,
			Path:      f.Path,
		})
	}
	return json.Marshal(raw)
}

type forward struct {
	Protocol  string `json:"protocol"`
	DstPrefix string `json:"dst_prefix"`
	DstPort   int    `json:"dst_port"`
	Path      string `json:"path"`
}
