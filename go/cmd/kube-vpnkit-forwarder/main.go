package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// TODO implement updateProxy
// TODO emit Kubernetes events on errors (and perhaps success), so they can be observed by the user (via `kubectl get events`
//      or `kubectl describe service`), make sure errors user sees are meaningful

func main() {
	flag.Parse()

	log.Println("Starting kube-vpnkit-forwarder...")

	fwd := newForwarder()

	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		log.Fatal(err)
	}

	restClient := clientset.Core().RESTClient()
	watchlist := cache.NewListWatchFromClient(restClient, "services", corev1.NamespaceAll, fields.Everything())

	resyncPeriod := 30 * time.Second

	_, controller := cache.NewInformer(watchlist, &corev1.Service{}, resyncPeriod,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				fwd.addProxy(obj.(*corev1.Service))
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				log.Println("updateProxy not implemented")
			},
			DeleteFunc: func(obj interface{}) {
				fwd.deleteProxy(serviceName(obj.(*corev1.Service)))
			},
		},
	)

	stop := make(chan struct{})
	go controller.Run(stop)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	<-signalChan

	log.Println("Shutdown signal received, exiting...")
	close(stop)
	fwd.deleteAllProxies()
}
