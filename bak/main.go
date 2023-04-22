package main

import (
	"crypto/md5"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/songgao/water/waterutil"
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
	ipProto := waterutil.IPv4Protocol(data)
	// 访问协议
	var accessProto uint8
	// 只统计 tcp和udp 的访问
	switch ipProto {
	case waterutil.TCP:
		accessProto = acc_proto_tcp
	case waterutil.UDP:
		accessProto = acc_proto_udp
	}


	packetData.SrcIP = string(waterutil.IPv4Source(data))
	packetData.DstIP = string(waterutil.IPv4Destination(data))
	packetData.DstPort = string(waterutil.IPv4DestinationPort(data))


	info := ""
	nu := utils.NowSec().Unix()
	if ipProto == waterutil.TCP {
		tcpPlData := waterutil.IPv4Payload(data)
		// 24 (ACK PSH)
		if len(tcpPlData) < 14 || tcpPlData[13] != 24 {
			return nil, nil
		}
		accessProto, info = onTCP(tcpPlData)
		// HTTPS or HTTP
		if accessProto != acc_proto_tcp {
			// 提前存储只含ip数据的key, 避免即记录域名又记录一笔IP数据的记录
			ipKey := make([]byte, 51)
			copy(ipKey, key)
			ipS := utils.BytesToString(ipKey)
			auditPayload.IpAuditMap.Set(ipS, nu)

			key[34] = byte(accessProto)
			// 存储含域名的key
			if info != "" {
				md5Sum := md5.Sum([]byte(info))
				copy(key[35:51], md5Sum[:])
			}
		}
	}
	s := utils.BytesToString(key)



	//packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)

	//// Get the network layer (IPv4 or IPv6)
	//networkLayer := packet.NetworkLayer()
	//if networkLayer != nil {
	//	packetData.SrcIP = networkLayer.NetworkFlow().Src().String()
	//	packetData.DstIP = networkLayer.NetworkFlow().Dst().String()
	//}
	//
	//// TODO: Get vpn username from occtl via srcIP and put in a cache, before write to db, attach the username
	//packetData.Username = "testuser"

	//transportLayer := packet.TransportLayer()
	//if transportLayer != nil {
	//	// Get the transport layer (TCP, UDP or SCTP)
	//	packetData.DstPort = transportLayer.TransportFlow().Dst().String()
	//	//for _, parser := range test.TcpParsers {
	//	//	if proto, info := parser(data); proto ==2 {
	//	//		fmt.Println(proto,info)
	//	//		packetData.DstHost = info
	//	//		return packetData,nil
	//	//	}
	//	//}
	//	_, b := test.SniNewParser(transportLayer.LayerPayload())
	//	if b != "" {
	//		packetData.DstHost = b
	//		//fmt.Println(packetData)
	//	}
	//}

	//if packetData.DstHost == ""{
	//	packetData.DstHost = packetData.DstIP
	//}

	return packetData, nil
}

//func ParsePacket(data []byte) (*PacketData, error) {
//	packetData := &PacketData{}
//	packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
//
//	// Get the network layer (IPv4 or IPv6)
//	networkLayer := packet.NetworkLayer()
//	if networkLayer != nil {
//		packetData.SrcIP = networkLayer.NetworkFlow().Src().String()
//		packetData.DstIP = networkLayer.NetworkFlow().Dst().String()
//	}
//
//	// TODO: Get vpn username from occtl via srcIP and put in a cache, before write to db, attach the username
//	packetData.Username = "testuser"
//
//	transportLayer := packet.TransportLayer()
//	if transportLayer != nil {
//		// Get the transport layer (TCP, UDP or SCTP)
//		packetData.DstPort = transportLayer.TransportFlow().Dst().String()
//		//for _, parser := range test.TcpParsers {
//		//	if proto, info := parser(data); proto ==2 {
//		//		fmt.Println(proto,info)
//		//		packetData.DstHost = info
//		//		return packetData,nil
//		//	}
//		//}
//		_, b := test.SniNewParser(transportLayer.LayerPayload())
//		if b != "" {
//			packetData.DstHost = b
//			//fmt.Println(packetData)
//		}
//	}
//
//	//if packetData.DstHost == ""{
//	//	packetData.DstHost = packetData.DstIP
//	//}
//
//	return packetData, nil
//}

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
	//handle.SetBPFFilter(filter)
	defer handle.Close()

	auditPayload := &AuditPayload{IpAuditMap: utils.NewMap("cmap", 0)}
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

			} else {
				auditPayload.IpAuditMap.Set(clientKey, packetData)
				fmt.Println("New Client:", clientKey)
			}
		} else {
			fmt.Println("New Client1:", clientKey)
		}

	}
}
