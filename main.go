package main

import (
	"github.com/wukongcloud/netcap/handler"
	"regexp"
)

func main() {
	// Define the pattern that matching interfaces should have in their name
	ifacePattern := regexp.MustCompile(`(^en\d+)|(vpns\d+)`)

	// Create a channel to receive interface updates
	ifaceUpdates := make(chan []handler.Interface)

	// Start the goroutine to capture traffic on the interfaces
	go handler.CaptureLoop(ifaceUpdates)

	// Start the goroutine to watch for changes in the network interfaces
	go handler.WatchInterfaces(ifacePattern, ifaceUpdates)

	// Block the main goroutine so that the program doesn't exit
	select {}
}
