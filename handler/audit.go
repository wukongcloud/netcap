package handler

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/wukongcloud/netcap/model"
	"github.com/wukongcloud/netcap/utils"
	"github.com/wukongcloud/netcap/utils/parser"
	"log"
	"strconv"
	"strings"
	"time"
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
		ipv6, _ := ipv6Layer.(*layers.IPv6)
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

	// only process the traffic srcIP start with 192.168
	if strings.HasPrefix(srcIP, "192.168") == true {
		// if interface not exist or expired Set interface detail, else get from cache
		val, ok := networkInterface.NetworkInterface.Get(iface.Name)
		if !ok || time.Now().Unix()-val.(Interface).JoinTime > 30 {
			networkInterface.NetworkInterface.Set(iface.Name, getInterfaceDetail(iface))
		} else {
			val, _ = networkInterface.NetworkInterface.Get(iface.Name)
			iface = val.(Interface)
		}

		// clientKey is a uniq visit for a client, if exist and expire delete it, else set a new one
		clientKey := fmt.Sprintf("%s_%s_%s_%s", srcIP, dstIP, dstPort, hostname)
		ts, ok := auditPayload.IpAuditMap.Get(clientKey)
		if ok && time.Now().Unix()-ts.(int64) > int64(30) {
			auditPayload.IpAuditMap.Del(clientKey)
		} else if !ok {
			auditPayload.IpAuditMap.Set(clientKey, utils.NowSec().Unix())
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
			log.Println("[audit]", packetData)
		}
	}
}
