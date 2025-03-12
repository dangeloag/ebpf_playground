package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

var ifaceName string

func main() {

	flag.StringVar(&ifaceName, "iface", "lo", "pass the interface")
	flag.Parse()

	// Load pre-compiled eBPF program
	spec, err := ebpf.LoadCollectionSpec("xdp_filter.o")
	if err != nil {
		log.Fatalf("loading collection spec: %s", err)
	}

	objs := struct {
		XdpFilter *ebpf.Program `ebpf:"xdp_filter"`
	}{}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.XdpFilter.Close()

	// Attach the XDP program to a network interface
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("gettig interface %s: %s", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpFilter,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		log.Fatalf("attaching XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to interface %s", ifaceName)

	// Wait for a signal to terminate
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Received signal, exiting")
}
