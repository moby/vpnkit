package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moby/vpnkit/go/pkg/controller"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var path string

func main() {
	flag.StringVar(&path, "path", "", "unix socket to vpnkit port forward API")
	flag.Parse()

	log.Println("Starting kube-vpnkit-forwarder...")

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		log.Fatal(err)
	}

	resyncPeriod := 30 * time.Second

	informer := informers.NewSharedInformerFactory(clientset, resyncPeriod).Core().V1().Services().Informer()
	vpnkitClient, err := vpnkit.NewClient(path)
	if err != nil {
		log.Fatal(err)
	}
	controller := controller.New(vpnkitClient, clientset.CoreV1())
	defer controller.Dispose()

	informer.AddEventHandler(controller)

	stop := make(chan struct{})
	go informer.Run(stop)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	log.Println("Shutdown signal received, exiting...")
	close(stop)
}
