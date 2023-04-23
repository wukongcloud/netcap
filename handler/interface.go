package handler

import (
	"encoding/json"
	"fmt"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
	"github.com/wukongcloud/netcap/model"
	"log"
	"net"
	"os/exec"
	"regexp"
	"sync"
	"time"
)

type Interface struct {
	Name      string
	Username  string
	UserAgent string
	ServerIP  string
	ClientEIP string
	ClientIP  string
	Location  string
	Handle    *pcap.Handle
}

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

func getInterfaceDetail(iface Interface) Interface {
	// get data from occtl via device name

	var ocUsers model.OcUsers
	//usersCmd := exec.Command("echo", "[{\"ID\":1351,\"Username\":\"admin\",\"Groupname\":\"(none)\",\"State\":\"connected\",\"vhost\":\"default\",\"Device\":\"en0\",\"MTU\":\"1392\",\"Remote IP\":\"91.75.131.237\",\"Location\":\"unknown\",\"Local Device IP\":\"10.50.0.181\",\"IPv4\":\"192.168.10.165\",\"P-t-P IPv4\":\"192.168.10.1\",\"User-Agent\":\"AnyConnect Darwin_i386 4.10.05111\",\"RX\":\"935371\",\"TX\":\"13020214\",\"_RX\":\"935.4 KB\",\"_TX\":\"13.0 MB\",\"Average RX\":\"1.2 KB/sec\",\"Average TX\":\"16.1 KB/sec\",\"DPD\":\"90\",\"KeepAlive\":\"32400\",\"Connected at\":\"2023-04-23 10:38:56\",\"_Connected at\":\"13m:28s\",\"Full session\":\"jHonMFiAAa/V3aS7VrPBKon+Z6U=\",\"Session\":\"jHonMF\",\"TLS ciphersuite\":\"(TLS1.2)-(ECDHE-SECP256R1)-(RSA-PSS-RSAE-SHA256)-(AES-256-GCM)\",\"DNS\":[],\"NBNS\":[],\"Split-DNS-Domains\":[],\"Routes\":[\"10.50.0.0/255.255.0.0\",\"10.54.0.0/255.255.0.0\",\"10.70.0.0/255.255.0.0\"],\"No-routes\":[],\"iRoutes\":[],\"Restricted to routes\":\"False\",\"Restricted to ports\":[]}]")
	usersCmd := exec.Command("occtl", []string{"-j", "show", "users"}...)
	usersOutput, err := usersCmd.Output()
	if err != nil {
		fmt.Println("get user error")
	}

	if err := json.Unmarshal(usersOutput, &ocUsers); err != nil {
		fmt.Println("json unmarshal error")
	}

	var ifaceDetail = iface
	for _, u := range ocUsers {
		if u.Device != iface.Name {
			continue
		} else {
			ifaceDetail.Username = u.Username
			ifaceDetail.UserAgent = u.UserAgent
			ifaceDetail.ServerIP = u.LocalDeviceIP
			ifaceDetail.ClientIP = u.IPv4
			ifaceDetail.ClientEIP = u.RemoteIP
			ifaceDetail.Location = GetGEOInfo(u.RemoteIP)
		}
	}
	return ifaceDetail
}

func GetGEOInfo(ipStr string) string {
	db, err := geoip2.Open("./geoip/GeoLite2-City.mmdb")
	if err != nil {
		return "unknown"
	}
	defer db.Close()

	ip := net.ParseIP(ipStr)
	record, err := db.City(ip)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%s (%s)", record.City.Names["en"], record.Country.Names["en"])

	//fmt.Printf("Portuguese (BR) city name: %v\n", record.City.Names["zh-CN"])
	//fmt.Printf("Portuguese (BR) city name: %v\n", record.City.Names["zh-CN"])
	//fmt.Printf("English subdivision name: %v\n", record.Subdivisions[0].Names["en"])
	//fmt.Printf("Russian country name: %v\n", record.Country.Names["en"])
	//fmt.Printf("ISO country code: %v\n", record.Country.IsoCode)
	//fmt.Printf("Time zone: %v\n", record.Location.TimeZone)
	//fmt.Printf("Coordinates: %v, %v\n", record.Location.Latitude, record.Location.Longitude)

}
