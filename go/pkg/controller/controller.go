package controller

import (
	"context"
	"fmt"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"net"
)

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

// Dispose unexpose all ports previously exposed by this controller
func (c *Controller) Dispose() {
	_, dockerNet, err := net.ParseCIDR("172.17.0.0/16")
	if err != nil {
		log.Infof("Cannot parse default docker0 subnet: %v ", err)
		return
	}
	ports, err := c.client.ListExposed(context.Background())
	if err != nil {
		log.Infof("Cannot list exposed ports: %v", err)
		return
	}
	for _, port := range ports {
		if dockerNet.Contains(port.InIP) {
			continue
		}
		if err := c.client.Unexpose(context.Background(), &port); err != nil {
			log.Infof("cannot unexpose port: %v", err)
		}
	}
}

// OnAdd exposes port if necessary
func (c *Controller) OnAdd(obj interface{}) {
	if err := c.ensureOpened(obj); err != nil {
		log.Errorf("OnAdd failed: %v", err)
	}
}

// OnUpdate exposes port if necessary
func (c *Controller) OnUpdate(oldObj, newObj interface{}) {
	if err := c.ensureOpened(newObj); err != nil {
		log.Errorf("OnUpdate failed: %v", err)
	}
}

func (c *Controller) ensureOpened(obj interface{}) error {
	service, ok := obj.(*v1.Service)
	if !ok {
		return fmt.Errorf("received an invalid object, was expecting v1.Service")
	}
	opened, err := c.client.ListExposed(context.Background())
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
		if err := c.client.Expose(context.Background(), &port); err != nil {
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
		if _, err := c.services.Services(service.Namespace).UpdateStatus(copy); err != nil {
			log.Errorf("Cannot update service status %s: %v", service.Name, err)
		}
	}
	return nil
}

func contains(s []vpnkit.Port, e vpnkit.Port) bool {
	for _, a := range s {
		if a.Proto == e.Proto &&
			a.OutPort == e.OutPort &&
			a.InIP.Equal(e.InIP) &&
			a.InPort == e.InPort {
			return true
		}
	}
	return false
}

func alreadyOpened(s []vpnkit.Port, e vpnkit.Port) bool {
	for _, a := range s {
		if a.OutPort == e.OutPort {
			return true
		}
	}
	return false
}

// OnDelete unexposes port
func (c *Controller) OnDelete(obj interface{}) {
	service, ok := obj.(*v1.Service)
	if !ok {
		log.Errorf("OnDelete handler received an invalid object, was expecting v1.Service")
		return
	}
	for _, port := range servicePorts(service) {
		if err := c.client.Unexpose(context.Background(), &port); err != nil {
			log.Errorf("cannot unexpose port: %s", err)
			continue
		}
		log.Infof("Closed port %d", port.OutPort)
	}
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
			Proto:   protocol,
			OutIP:   net.ParseIP("0.0.0.0"),
			OutPort: uint16(servicePort.Port),
			InIP:    net.ParseIP(service.Spec.ClusterIP),
			InPort:  uint16(servicePort.Port),
		}, nil
	case v1.ServiceTypeNodePort:
		if servicePort.NodePort == 0 {
			return nil, errors.New("NodePort is 0")
		}
		return &vpnkit.Port{
			Proto:   protocol,
			OutIP:   net.ParseIP("0.0.0.0"),
			OutPort: uint16(servicePort.NodePort),
			InIP:    net.ParseIP(service.Spec.ClusterIP),
			InPort:  uint16(servicePort.Port),
		}, nil
	case v1.ServiceTypeClusterIP:
		return nil, nil
	default:
		return nil, errors.Errorf("Unknown service type %s", service.Spec.Type)
	}
}
