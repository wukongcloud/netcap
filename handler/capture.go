package handler

import (
	"github.com/google/gopacket"
	"sync"
)

const (
	acc_proto_udp = iota + 1
	acc_proto_tcp
	acc_proto_https
	acc_proto_http
)

func CaptureLoop(ifaceUpdates <-chan []Interface) {

	// Create a map to hold the packet counts for each interface
	counts := make(map[string]int64)

	// Create a mutex to synchronize access to the counts map
	var mutex sync.Mutex

	// Start the loop to capture traffic on the interfaces
	for {
		// Wait for an update to the list of interfaces
		interfaces := <-ifaceUpdates

		// Iterate over the interfaces and start capturing traffic
		for _, iface := range interfaces {
			//fmt.Println(iface.Name)
			go func(iface Interface) {
				// Create a packet capture filter to capture only TCP traffic
				//filter := "tcp"

				// Create a packet capture handle
				packetSource := gopacket.NewPacketSource(iface.Handle, iface.Handle.LinkType()).Packets()

				// Start capturing packets and processing them
				for packet := range packetSource {
					audit(iface, packet)
					// Update the packet count for the interface
					mutex.Lock()
					counts[iface.Name]++
					mutex.Unlock()
				}
			}(iface)
		}
	}
}
