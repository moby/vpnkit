package controller

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	kubernetes "k8s.io/client-go/kubernetes/fake"
	core "k8s.io/client-go/testing"
)

func TestNodePortService(t *testing.T) {
	client := mockVpnKitClient{}
	kubeClient := kubernetes.NewSimpleClientset()
	controller := New(&client, kubeClient.CoreV1())
	service := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "service1",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: v1.ProtocolTCP,
					Port:     8080,
					NodePort: 8080,
				},
			},
			ClusterIP: "10.0.0.1",
		},
	}

	controller.OnAdd(&service)

	assert.EqualValues(t, client.exposed, []vpnkit.Port{
		{
			Proto:      vpnkit.TCP,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    8080,
			InIP:       net.ParseIP("10.0.0.1"),
			InPort:     8080,
			Annotation: annotation,
		},
	})
	assert.Contains(t, kubeClient.Fake.Actions(), core.NewUpdateSubresourceAction(
		schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"},
		"status",
		"ns1",
		&v1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "ns1",
				Name:      "service1",
			},
			Spec: v1.ServiceSpec{
				Type: v1.ServiceTypeNodePort,
				Ports: []v1.ServicePort{
					{
						Protocol: v1.ProtocolTCP,
						Port:     8080,
						NodePort: 8080,
					},
				},
				ClusterIP: "10.0.0.1",
			},
			Status: v1.ServiceStatus{
				LoadBalancer: v1.LoadBalancerStatus{
					Ingress: []v1.LoadBalancerIngress{
						{
							Hostname: "localhost",
						},
					},
				},
			},
		},
	))

	controller.OnDelete(&service)
	assert.Len(t, client.exposed, 0)
}

func TestLoadBalancerService(t *testing.T) {
	client := mockVpnKitClient{}
	controller := New(&client, kubernetes.NewSimpleClientset().CoreV1())

	service := v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Name:       "web",
					Protocol:   v1.ProtocolTCP,
					Port:       80,
					TargetPort: intstr.FromInt(8080),
					NodePort:   30185,
				},
			},
			ClusterIP: "10.96.48.189",
		},
	}

	controller.OnAdd(&service)
	assert.EqualValues(t, client.exposed, []vpnkit.Port{
		{
			Proto:      vpnkit.TCP,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    80,
			InIP:       net.ParseIP("10.96.48.189"),
			InPort:     80,
			Annotation: annotation,
		},
	})
}

func TestAddTwice(t *testing.T) {
	client := mockVpnKitClient{}
	kubeClient := kubernetes.NewSimpleClientset()
	controller := New(&client, kubeClient.CoreV1())

	service := v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Name:     "web",
					Protocol: v1.ProtocolTCP,
					Port:     80,
					NodePort: 30185,
				},
			},
			ClusterIP: "10.96.48.189",
		},
	}

	controller.OnAdd(&service)
	controller.OnUpdate(&service, &service)
	assert.Len(t, client.exposed, 1)
	assert.Len(t, kubeClient.Fake.Actions(), 1)
}

func TestOverlappingPorts(t *testing.T) {
	client := mockVpnKitClient{}
	controller := New(&client, kubernetes.NewSimpleClientset().CoreV1())

	controller.OnAdd(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "service1",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Name:     "web",
					Protocol: v1.ProtocolTCP,
					Port:     80,
					NodePort: 30185,
				},
			},
			ClusterIP: "10.96.48.189",
		},
	})

	controller.OnAdd(&v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "service2",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					Name:     "http",
					Protocol: v1.ProtocolTCP,
					Port:     80,
					NodePort: 12345,
				},
				{
					Name:     "https",
					Protocol: v1.ProtocolTCP,
					Port:     443,
					NodePort: 12346,
				},
			},
			ClusterIP: "10.96.48.190",
		},
	})

	assert.EqualValues(t, client.exposed, []vpnkit.Port{
		{
			Proto:      vpnkit.TCP,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    80,
			InIP:       net.ParseIP("10.96.48.189"),
			InPort:     80,
			Annotation: annotation,
		},
		{
			Proto:      vpnkit.TCP,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    443,
			InIP:       net.ParseIP("10.96.48.190"),
			InPort:     443,
			Annotation: annotation,
		},
	})
}

func TestControllerDispose(t *testing.T) {
	client := mockVpnKitClient{}
	otherPort := vpnkit.Port{
		Proto:   "unix",
		InPath:  "/run/docker.sock",
		OutPath: "/var/run/docker.sock",
	}
	client.Expose(context.Background(), &otherPort)
	controller := New(&client, kubernetes.NewSimpleClientset().CoreV1())

	controller.OnAdd(&v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: v1.ProtocolTCP,
					Port:     8080,
					NodePort: 8080,
				},
			},
			ClusterIP: "10.0.0.1",
		},
	})

	assert.Equal(t, 2, len(client.exposed))

	controller.Dispose()

	assert.Equal(t, 1, len(client.exposed))
	assert.EqualValues(t, client.exposed, []vpnkit.Port{otherPort})
}

func TestDiscardClusterIPService(t *testing.T) {
	client := mockVpnKitClient{}
	controller := New(&client, kubernetes.NewSimpleClientset().CoreV1())

	controller.OnAdd(&v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{
					Name:     "web",
					Protocol: v1.ProtocolTCP,
					Port:     8080,
				},
			},
			ClusterIP: "10.0.0.1",
		},
	})

	assert.Len(t, client.exposed, 0)
}

func TestCloseUnusedPortsAfterUpdate(t *testing.T) {
	client := mockVpnKitClient{}
	kubeClient := kubernetes.NewSimpleClientset()
	controller := New(&client, kubeClient.CoreV1())

	source := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "service1",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: v1.ProtocolTCP,
					Port:     8080,
					NodePort: 8080,
				},
			},
			ClusterIP: "10.0.0.1",
		},
	}
	controller.OnAdd(&source)

	controller.OnUpdate(&source, &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "ns1",
			Name:      "service1",
		},
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeNodePort,
			Ports: []v1.ServicePort{
				{
					Protocol: v1.ProtocolTCP,
					Port:     9090,
					NodePort: 9090,
				},
			},
			ClusterIP: "10.0.0.2",
		},
	})

	assert.EqualValues(t, client.exposed, []vpnkit.Port{
		{
			Proto:      vpnkit.TCP,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    9090,
			InIP:       net.ParseIP("10.0.0.2"),
			InPort:     9090,
			Annotation: annotation,
		},
	})
}

type mockVpnKitClient struct {
	exposed []vpnkit.Port
}

func (c *mockVpnKitClient) Expose(_ context.Context, port *vpnkit.Port) error {
	c.exposed = append(c.exposed, *port)
	return nil
}

func (c *mockVpnKitClient) Unexpose(_ context.Context, port *vpnkit.Port) error {
	var next []vpnkit.Port
	for _, exposed := range c.exposed {
		if exposed.Proto != port.Proto || exposed.OutPort != port.OutPort {
			next = append(next, exposed)
		}
	}
	c.exposed = next
	return nil
}

func (c *mockVpnKitClient) ListExposed(_ context.Context) ([]vpnkit.Port, error) {
	return c.exposed, nil
}

func (c *mockVpnKitClient) DumpState(_ context.Context, _ io.Writer) error {
	return nil
}
