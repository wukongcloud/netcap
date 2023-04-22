package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wukongcloud/netcap/test"
	"github.com/wukongcloud/netcap/utils"
	"strings"
	"time"
)

const (
	expirationPeriod = 60 * time.Second
)

const (
	acc_proto_udp = iota + 1
	acc_proto_tcp
	acc_proto_https
	acc_proto_http
)

type AuditPayload struct {
	IpAuditMap utils.IMaps
}

type PacketData struct {
	Username string
	SrcIP    string
	DstIP    string
	DstPort  string
	DstHost  string
}



func ParsePacket(data []byte) (*PacketData, error) {
	packetData := &PacketData{}
	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	// Get the network layer (IPv4 or IPv6)
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		packetData.SrcIP = networkLayer.NetworkFlow().Src().String()
		packetData.DstIP = networkLayer.NetworkFlow().Dst().String()
	}

	// TODO: Get vpn username from occtl via srcIP and put in a cache, before write to db, attach the username
	packetData.Username = "testuser"

	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		// Get the transport layer (TCP, UDP or SCTP)
		packetData.DstPort = transportLayer.TransportFlow().Dst().String()
		//for _, parser := range test.TcpParsers {
		//	if proto, info := parser(data); proto ==2 {
		//		fmt.Println(proto,info)
		//		packetData.DstHost = info
		//		return packetData,nil
		//	}
		//}
		_, b := test.SniNewParser(transportLayer.LayerPayload())
		if b != "" {
			packetData.DstHost = b
			//fmt.Println(packetData)
		}
	}

	//if packetData.DstHost == ""{
	//	packetData.DstHost = packetData.DstIP
	//}

	return packetData, nil
}

//func ProcessPacket(auditPayload *AuditPayload, packetData *PacketData) {
//	clientKey := packetData.SrcIP + "_" + packetData.DstIP + "_" + packetData.DstPort + "_" + packetData.DstHost
//
//	if ok := strings.HasPrefix(clientKey, "192.168"); ok {
//		if _, ok := auditPayload.IpAuditMap.Get(clientKey); !ok {
//			auditPayload.IpAuditMap.Set(clientKey, packetData.DstHost)
//		}else {
//			fmt.Println("New Client:", clientKey)
//		}
//
//	}
//}

//func ExpireClients() {
//	for {
//		for k, v := range clientMap {
//			if time.Now().Sub(v.LastPacketTime) > v.ExpirationPeriod {
//				fmt.Println("Client expired:", k)
//				delete(clientMap, k)
//			}
//		}
//		time.Sleep(expirationPeriod / 60)
//	}
//}

func main() {
	const defaultSnapLen = 262144
	const filter = "ip &&(tcp || udp )&& ip.src==192.168.0.0/24 &&(tcp.dstport <=10000||udp.dstport <=10000) && not tcp.flags.ack == 1"
	//handle.SetBPFFilter("ip || tcp || tls")
	handle, err := pcap.OpenLive("en0", defaultSnapLen, true,
		pcap.BlockForever)
	if err != nil {
		panic(err.Error())
	}
	handle.SetBPFFilter(filter)
	defer handle.Close()

	auditPayload := &AuditPayload{IpAuditMap: utils.NewMap("cmap", 0),}
	packets := gopacket.NewPacketSource(
		handle, handle.LinkType()).Packets()

	//go ExpireClients()


	for packet := range packets {
		packetData, err := ParsePacket(packet.Data())
		if err != nil {
			fmt.Println("Error parsing packet:", err)
			continue
		}

		//fmt.Printf("Packet Data: %+v\n", packetData)
		clientKey := packetData.SrcIP + "_" + packetData.DstIP + "_" + packetData.DstPort + "_" + packetData.DstHost

		if ok := strings.HasPrefix(clientKey, "192.168"); ok {
			if _, ok := auditPayload.IpAuditMap.Get(clientKey); ok {

			}else {
				auditPayload.IpAuditMap.Set(clientKey, packetData)
				fmt.Println("New Client:", clientKey)
			}

		}
	}
}
