package main

import (
	"fmt"
	"log"
	"net"

	"github.com/moby/vpnkit/go/pkg/libproxy"

	corev1 "k8s.io/api/core/v1"
)

type forwarder struct {
	proxies map[string]*serviceProxy
}

type serviceProxy struct {
	ports map[int]*portProxy
}

type portProxy struct {
	close    chan struct{}
	external net.Addr
	internal net.Addr
}

func serviceName(service *corev1.Service) string {
	return fmt.Sprintf("%s/%s", service.Namespace, service.Name)
}

func newForwarder() *forwarder {
	return &forwarder{
		proxies: make(map[string]*serviceProxy),
	}
}

func (f *forwarder) addProxy(service *corev1.Service) {
	proxy := &serviceProxy{
		ports: make(map[int]*portProxy),
	}

	name := serviceName(service)

	for i, p := range service.Spec.Ports {
		if err := proxy.addPortProxy(p, i, service.Spec.ClusterIP); err != nil {
			log.Printf("Error while creating proxy for %s (port #%d) – %v", name, i, err)
			continue
		}
		go func(i int) {
			if err := proxy.ports[i].run(); err != nil {
				log.Printf("Error while starting proxy for %s (port #%d) – %v", name, i, err)
				return
			}
		}(i)
	}

	f.proxies[name] = proxy
}

func (f *forwarder) deleteAllProxies() {
	for k := range f.proxies {
		f.deleteProxy(k)
	}
}

func (f *forwarder) deleteProxy(name string) {
	if s, ok := f.proxies[name]; ok {
		s.deleteAllPortProxies()
		delete(f.proxies, name)
		log.Printf("Deleted proxy for %s", name)
	}
}

func (s *serviceProxy) addPortProxy(p corev1.ServicePort, portIndex int, clusterIP string) error {
	proxy := &portProxy{
		close: make(chan struct{}),
	}

	if p.NodePort == 0 {
		return fmt.Errorf("cannot use service.Spec.Ports[%d].NodePort=%d", portIndex, p.NodePort)
	}

	internalAddr := net.ParseIP("0.0.0.0")
	externalAddr := net.ParseIP(clusterIP)
	if externalAddr == nil {
		return fmt.Errorf("cannot parse service.Spec.ClusterIP=%s", clusterIP)
	}

	switch p.Protocol {
	case corev1.ProtocolUDP:
		proxy.external = &net.UDPAddr{IP: externalAddr, Port: int(p.NodePort)}
		proxy.internal = &net.UDPAddr{IP: internalAddr, Port: int(p.Port)}
	case corev1.ProtocolTCP:
		fallthrough
	default:
		proxy.external = &net.TCPAddr{IP: externalAddr, Port: int(p.NodePort)}
		proxy.internal = &net.TCPAddr{IP: internalAddr, Port: int(p.Port)}
	}

	s.ports[portIndex] = proxy
	return nil
}

func (s *serviceProxy) deleteAllPortProxies() {
	for i, p := range s.ports {
		close(p.close)
		delete(s.ports, i)
	}
}

func (p *portProxy) run() error {
	desc := fmt.Sprintf("internal=%s external=%s", p.internal.String(), p.external.String())
	proxy, err := libproxy.NewBestEffortIPProxy(p.external, p.internal)
	if err != nil {
		return fmt.Errorf("cannot create proxy for port %s – %v", desc, err)
	}

	ctl, err := libproxy.ExposePort(p.external, p.internal)
	if err != nil {
		return fmt.Errorf("cannot expose port %s – %v", desc, err)
	}

	if proxy != nil {
		proxy.Run()
	} else {
		return fmt.Errorf("unexpected error – proxy for %s is nil", desc)
	}

	<-p.close
	ctl.Close()
	return nil
}
