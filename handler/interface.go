package handler

import (
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"regexp"
	"sync"
	"time"
)

func WatchInterfaces(ifacePattern *regexp.Regexp, ifaceUpdates chan<- []Interface) {
	// Create a slice to hold the matching interfaces
	interfaces := make([]Interface, 0)

	// Create a mutex to synchronize access to the interfaces slice
	var mutex sync.Mutex

	// Start the periodic loop to check for new interfaces
	for {
		// Get a list of all network interfaces on the system
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Println(err)
			continue
		}

		// Create a slice to hold the new set of matching interfaces
		newInterfaces := make([]Interface, 0)

		// Iterate over the interfaces and capture traffic on matching ones
		for _, iface := range ifaces {
			// Check if the interface name matches the pattern
			if ifacePattern.MatchString(iface.Name) {
				// Check if the interface is already being captured
				mutex.Lock()
				found := false
				for _, i := range interfaces {
					if i.Name == iface.Name {
						newInterfaces = append(newInterfaces, i)
						found = true
						break
					}
				}
				if found {
					mutex.Unlock()
					continue
				}

				// Open a handle to the interface
				handle, err := pcap.OpenLive(iface.Name, 1600, true, 100*time.Millisecond)
				if err != nil {
					log.Printf("Failed to open interface %s: %v", iface.Name, err)
					mutex.Unlock()
					continue
				}

				// Set a BPF filter to capture only TCP traffic
				if err := handle.SetBPFFilter("tcp"); err != nil {
					log.Printf("Failed to set BPF filter on interface %s: %v", iface.Name, err)
					handle.Close()
					mutex.Unlock()
					continue
				}

				// Add the interface to the list
				newInterfaces = append(newInterfaces, Interface{Name: iface.Name, Handle: handle})
				mutex.Unlock()
			}
		}

		// Check if any interfaces have disappeared
		mutex.Lock()
		for i := 0; i < len(interfaces); i++ {
			found := false
			for _, iface := range ifaces {
				if iface.Name == interfaces[i].Name {
					found = true
					break
				}
			}
			if !found {
				log.Printf("Interface %s has disappeared, removing from capture", interfaces[i].Name)
				if err := interfaces[i].Handle.Close; err != nil {
					log.Printf("Failed to close handle for interface %s: %v", interfaces[i].Name, err)
				}
				interfaces = append(interfaces[:i], interfaces[i+1:]...)
				i--
			}
		}
		mutex.Unlock()

		// Send the new list of interfaces to the capture goroutine
		ifaceUpdates <- newInterfaces

		// Wait for a short time before checking for updates again
		time.Sleep(5 * time.Second)
	}
}

