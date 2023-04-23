package handler

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/wukongcloud/netcap/model"
	"github.com/wukongcloud/netcap/utils"
	"github.com/wukongcloud/netcap/utils/parser"
	"strconv"
	"strings"
)

type AuditPayload struct {
	IpAuditMap       utils.IMaps
	NetworkInterface utils.IMaps
}

var auditPayload = &AuditPayload{
	IpAuditMap: utils.NewMap("cmap", 0)}

var networkInterface = &AuditPayload{
	NetworkInterface: utils.NewMap("cmap", 0),
}

func audit(iface Interface, packet gopacket.Packet) {

	// Get the source and destination IP addresses
	ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
	ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
	var (
		srcIP string
		dstIP string
	)
	if ipv4Layer != nil {
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	}
	if ipv6Layer != nil {
		ipv6, _ := ipv4Layer.(*layers.IPv4)
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	}

	// Get the source and destination ports
	var (
		hostname string
		srcPort  string
		dstPort  string
	)

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			srcPort = strconv.Itoa(int(tcp.SrcPort))
			dstPort = strconv.Itoa(int(tcp.DstPort))
		}
		_, hostname = parser.SniNewParser(tcpLayer.LayerPayload())
	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		if udp, ok := udpLayer.(*layers.UDP); ok {
			srcPort = strconv.Itoa(int(udp.SrcPort))
			dstPort = strconv.Itoa(int(udp.DstPort))

		}
	}

	if _, ok := networkInterface.NetworkInterface.Get(iface.Name); !ok {
		iface = getInterfaceDetail(iface)
		networkInterface.NetworkInterface.Set(iface.Name, iface)
		//fmt.Println(iface)
	} else {
		val, _ := networkInterface.NetworkInterface.Get(iface.Name)
		iface = val.(Interface)
	}

	packetData := model.PacketData{
		NIC:       iface.Name,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		DstHost:   hostname,
		Username:  iface.Username,
		UserAgent: iface.UserAgent,
		ServerIP:  iface.ServerIP,
		ClientEIP: iface.ClientEIP,
		ClientIP:  iface.ClientIP,
		Location:  iface.Location,
	}

	clientKey := fmt.Sprintf("%s_%s_%s_%s_%s", packetData.SrcIP, packetData.Username, packetData.DstIP, packetData.DstPort, packetData.DstHost)

	if ok := strings.HasPrefix(clientKey, "192.168"); ok {
		if val, _ := auditPayload.IpAuditMap.Get(clientKey); val == nil {
			auditPayload.IpAuditMap.Set(clientKey, packetData)
			//fmt.Println("New Client:", clientKey)
			fmt.Println(packetData)
			//fmt.Println(
			//	packetData.Username,
			//	packetData.SrcIP,
			//	packetData.DstIP,
			//	packetData.DstPort,
			//	packetData.DstHost,
			//	packetData.ClientEIP,
			//	packetData.Location,
			//	packetData.UserAgent,
			//	)
			//fmt.Println(fmt.Sprintf(""))
		}
	}
}
