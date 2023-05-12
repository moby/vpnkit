package controller

import (
	"context"
	"fmt"
	"net"

	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/tools/cache"
)

const annotation = "vpnkit-k8s-controller"

// Controller kubernetes controller used by Docker Desktop
type Controller struct {
	services corev1client.ServicesGetter
	client   vpnkit.Client
}

// New creates a new controller
func New(client vpnkit.Client, services corev1client.ServicesGetter) *Controller {
	return &Controller{
		services: services,
		client:   client,
	}
}

var _ cache.ResourceEventHandler = &Controller{}

// Dispose unexpose all ports previously exposed by this controller
func (c *Controller) Dispose() {
	ctx := context.Background()
	ports, err := c.client.ListExposed(ctx)
	if err != nil {
		log.Infof("Cannot list exposed ports: %v", err)
		return
	}
	for _, port := range ports {
		if port.Annotation != annotation {
			continue
		}
		if err := c.client.Unexpose(ctx, &port); err != nil {
			log.Infof("cannot unexpose port: %v", err)
		}
	}
}

// OnAdd exposes port if necessary
func (c *Controller) OnAdd(obj interface{}, _ bool) {
	if err := c.ensureOpened(obj); err != nil {
		log.Errorf("OnAdd failed: %v", err)
	}
}

// OnUpdate exposes port if necessary
func (c *Controller) OnUpdate(oldObj, newObj interface{}) {
	if err := c.closeAbsentPorts(oldObj, newObj); err != nil {
		log.Errorf("OnUpdate failed: %v", err)
	}
	if err := c.ensureOpened(newObj); err != nil {
		log.Errorf("OnUpdate failed: %v", err)
	}
}

// OnDelete unexposes port
func (c *Controller) OnDelete(obj interface{}) {
	if err := c.closeAbsentPorts(obj, &v1.Service{}); err != nil {
		log.Errorf("OnUpdate failed: %v", err)
	}
}

func (c *Controller) closeAbsentPorts(oldObj, newObj interface{}) error {
	oldService, ok := oldObj.(*v1.Service)
	if !ok {
		return fmt.Errorf("received an invalid object, was expecting v1.Service")
	}
	newService, ok := newObj.(*v1.Service)
	if !ok {
		return fmt.Errorf("received an invalid object, was expecting v1.Service")
	}
	newPorts := servicePorts(newService)
	for _, oldPort := range servicePorts(oldService) {
		if !contains(newPorts, oldPort) {
			if err := c.client.Unexpose(context.Background(), &oldPort); err != nil {
				log.Errorf("cannot unexpose port: %s", err)
				continue
			}
			log.Infof("Closed port %d", oldPort.OutPort)
		}
	}
	return nil
}

func (c *Controller) ensureOpened(obj interface{}) error {
	ctx := context.TODO()

	service, ok := obj.(*v1.Service)
	if !ok {
		return fmt.Errorf("received an invalid object, was expecting v1.Service")
	}
	opened, err := c.client.ListExposed(ctx)
	if err != nil {
		return errors.Wrap(err, "cannot list exposed ports")
	}

	for _, port := range servicePorts(service) {
		if alreadyOpened(opened, port) {
			log.Errorf("Port %d for service %s is already opened by another service", port.OutPort, service.Name)
			continue
		}
		if contains(opened, port) {
			log.Debugf("Port %d for service %s already opened", port.OutPort, service.Name)
			continue
		}
		if err := c.client.Expose(ctx, &port); err != nil {
			log.Debugf("cannot expose port: %v", err)
			continue
		}
		log.Infof("Opened port %d for service %s:%d", port.OutPort, service.Name, port.InPort)

		copy := service.DeepCopy()
		copy.Status.LoadBalancer = v1.LoadBalancerStatus{
			Ingress: []v1.LoadBalancerIngress{
				{
					Hostname: "localhost",
				},
			},
		}
		if _, err := c.services.Services(service.Namespace).UpdateStatus(
			ctx,
			copy,
			metav1.UpdateOptions{},
		); err != nil {
			log.Errorf("Cannot update service status %s: %v", service.Name, err)
		}
	}
	return nil
}

func contains(list []vpnkit.Port, given vpnkit.Port) bool {
	for _, current := range list {
		if equals(current, given) {
			return true
		}
	}
	return false
}

func equals(left vpnkit.Port, right vpnkit.Port) bool {
	return left.Proto == right.Proto &&
		left.OutPort == right.OutPort &&
		left.InIP.Equal(right.InIP) &&
		left.InPort == right.InPort
}

func alreadyOpened(s []vpnkit.Port, e vpnkit.Port) bool {
	for _, a := range s {
		if a.OutPort == e.OutPort {
			return true
		}
	}
	return false
}

func servicePorts(service *v1.Service) []vpnkit.Port {
	var ports []vpnkit.Port
	for _, servicePort := range service.Spec.Ports {
		port, err := convert(service, servicePort)
		if err != nil {
			log.Debugf("Discarded service %s: %v", service.Name, err)
			continue
		}
		if port != nil {
			ports = append(ports, *port)
		}
	}
	return ports
}

func convert(service *v1.Service, servicePort v1.ServicePort) (*vpnkit.Port, error) {
	var protocol vpnkit.Protocol
	switch servicePort.Protocol {
	case v1.ProtocolTCP:
		protocol = vpnkit.TCP
	case v1.ProtocolUDP:
		protocol = vpnkit.UDP
	default:
		return nil, errors.New("unrecognised servicePort.Protocol " + string(servicePort.Protocol))
	}
	switch service.Spec.Type {
	case v1.ServiceTypeLoadBalancer:
		return &vpnkit.Port{
			Proto:      protocol,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    uint16(servicePort.Port),
			InIP:       net.ParseIP(service.Spec.ClusterIP),
			InPort:     uint16(servicePort.Port),
			Annotation: annotation,
		}, nil
	case v1.ServiceTypeNodePort:
		if servicePort.NodePort == 0 {
			return nil, errors.New("NodePort is 0")
		}
		return &vpnkit.Port{
			Proto:      protocol,
			OutIP:      net.ParseIP("0.0.0.0"),
			OutPort:    uint16(servicePort.NodePort),
			InIP:       net.ParseIP(service.Spec.ClusterIP),
			InPort:     uint16(servicePort.Port),
			Annotation: annotation,
		}, nil
	case v1.ServiceTypeClusterIP:
		return nil, nil
	default:
		return nil, errors.Errorf("Unknown service type %s", service.Spec.Type)
	}
}
