package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/moby/vpnkit/go/pkg/controller"
	"github.com/moby/vpnkit/go/pkg/vpnkit"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const defaultLogLevel = log.InfoLevel

var path string
var logLevelName string

func main() {
	flag.StringVar(&path, "path", "", "unix socket to vpnkit port forward API")
	flag.StringVar(&logLevelName, "log-level", defaultLogLevel.String(), "log output level (error, warn, info, debug)")
	flag.Parse()

	if logLevel, err := log.ParseLevel(logLevelName); err == nil {
		log.SetLevel(logLevel)
	} else {
		log.SetLevel(defaultLogLevel)
		log.Warnf("Using default log level (%s): %v", defaultLogLevel.String(), err)
	}

	log.Println("Starting kube-vpnkit-forwarder...")

	rootCtx := context.Background()

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
	vpnkitController := controller.New(rootCtx, vpnkitClient, clientset.CoreV1())
	if _, err := informer.AddEventHandler(vpnkitController); err != nil {
		log.Fatal(err)
	}

	// stop signals to the informer to stop the controllers
	// informerDone signals that the informer has actually stopped running
	stop := make(chan struct{})
	informerDone := make(chan struct{})
	go func() {
		defer close(informerDone)
		informer.Run(stop)
	}()

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan
	log.Println("Shutdown signal received")
	close(stop)

	// allow the informer a chance to stop cleanly
	log.Println("Waiting for controller to finish")
	select {
	case <-time.After(10 * time.Second):
		log.Warn("Controller shutdown timed out")
	case <-informerDone:
	}

	// always attempt cleanup, even if the informer didn't stop nicely,
	// we can still hopefully unexpose any open ports
	log.Println("Cleaning up controller")
	cleanupCtx, cancel := context.WithTimeout(rootCtx, 15*time.Second)
	defer cancel()
	vpnkitController.Dispose(cleanupCtx)
}
