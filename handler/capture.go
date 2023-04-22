package handler

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/wukongcloud/netcap/model"
	"github.com/wukongcloud/netcap/utils"
	"github.com/wukongcloud/netcap/utils/parser"
	"strconv"
	"sync"
)

const (
	acc_proto_udp = iota + 1
	acc_proto_tcp
	acc_proto_https
	acc_proto_http
)

type Interface struct {
	Name   string
	Handle *pcap.Handle
}

type AuditPayload struct {
	IpAuditMap utils.IMaps
}

func CaptureLoop(ifaceUpdates <-chan []Interface) {
	//
	//auditPayload := &AuditPayload{IpAuditMap: utils.NewMap("cmap", 0)}

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
			fmt.Println(iface.Name)
			go func(iface Interface) {
				// Create a packet capture filter to capture only TCP traffic
				//filter := "tcp"

				// Create a packet capture handle
				packetSource := gopacket.NewPacketSource(iface.Handle, iface.Handle.LinkType()).Packets()

				// Start capturing packets and processing them
				for packet := range packetSource {

					//fmt.Println(packet.LinkLayer())
					//ipProto := waterutil.IPv4Protocol(packet.Data())
					//// 访问协议
					//var accessProto uint8
					//// 只统计 tcp和udp 的访问
					//switch ipProto {
					//case waterutil.TCP:
					//	accessProto = acc_proto_tcp
					//case waterutil.UDP:
					//	accessProto = acc_proto_udp
					//default:
					//	return
					//}

					//var packetData model.PacketData

					//fmt.Println(waterutil.IPv4Source(packet.Data()))

					//ipSrc := waterutil.IPv4Source(packet.NetworkLayer().LayerPayload())
					//ipDst := waterutil.IPv4Destination(packet.NetworkLayer().LayerPayload())
					//
					//portDst := waterutil.IPv4DestinationPort(packet.Data())

					//b := pool.GetByte51()
					//key := *b
					//copy(key[:16], ipSrc)
					//copy(key[16:32], ipDst)
					//binary.BigEndian.PutUint16(key[32:34], portDst)
					//
					//info := ""
					//nu := utils.NowSec().Unix()
					//if ipProto == waterutil.TCP {
					//	plData := waterutil.IPv4Payload(packet.Data())
					//	if len(plData) < 14 {
					//		return
					//	}
					//	flags := plData[13]
					//	switch flags {
					//	case flags & 0x20:
					//		// URG
					//		return
					//	case flags & 0x14:
					//		// RST ACK
					//		return
					//	case flags & 0x12:
					//		// SYN ACK
					//		return
					//	case flags & 0x11:
					//		// Client FIN
					//		return
					//	case flags & 0x10:
					//		// ACK
					//		return
					//	case flags & 0x08:
					//		// PSH
					//		return
					//	case flags & 0x04:
					//		// RST
					//		return
					//	case flags & 0x02:
					//		// SYN
					//		return
					//	case flags & 0x01:
					//		// FIN
					//		return
					//	case flags & 0x18:
					//		// PSH ACK
					//		accessProto, info = parser.OnTCP(plData)
					//		if info != "" {
					//			// 提前存储只含ip数据的key, 避免即记录域名又记录一笔IP数据的记录
					//			ipKey := make([]byte, 51)
					//			copy(ipKey, key)
					//			ipS := utils.BytesToString(ipKey)
					//			auditPayload.IpAuditMap.Set(ipS, nu)
					//			// 存储含域名的key
					//			key[34] = byte(accessProto)
					//			md5Sum := md5.Sum([]byte(info))
					//			copy(key[35:51], hex.EncodeToString(md5Sum[:]))
					//		}
					//		fmt.Println(info, "\n\n\n\n\n")
					//	case flags & 0x19:
					//		// URG
					//		return
					//	case flags & 0xC2:
					//		// SYN-ECE-CWR
					//		return
					//	}
					//}
					//s := utils.BytesToString(key)
					//
					//// 判断已经存在，并且没有过期
					//v, ok := auditPayload.IpAuditMap.Get(s)
					//if ok && nu-v.(int64) < int64(60) {
					//	// 回收byte对象
					//	pool.PutByte51(b)
					//	return
					//}

					// Get the source and destination IP addresses and ports
					ipLayer := packet.Layer(layers.LayerTypeIPv4)
					if ipLayer == nil {
						ipLayer = packet.Layer(layers.LayerTypeIPv6)
						if ipLayer == nil {
							continue
						}
					}
					//fmt.Println(ipLayer.LayerType())
					ip, _ := ipLayer.(*layers.IPv4)
					if ip == nil {
						//	ip, _ = ipLayer.(*layers.IPv6)
						//	if ip == nil {
						continue
						//	}
					}
					srcAddr := ip.SrcIP.String()
					dstAddr := ip.DstIP.String()

					//Extract the TCP layer from the packet
					tcpLayer := packet.Layer(layers.LayerTypeTCP)
					if tcpLayer == nil {
						continue
					}

					tcp, _ := tcpLayer.(*layers.TCP)
					//srcPort := tcp.SrcPort.String()
					dstPort := tcp.DstPort

					hostname := ""
					if tcpLayer != nil {
						_, hostname = parser.SniNewParser(tcpLayer.LayerPayload())
					}
					packetData := model.PacketData{
						Username: "sss",
						SrcIP:    string(srcAddr),
						DstIP:    string(dstAddr),
						DstPort:  strconv.Itoa(int(dstPort)),
						DstHost:  hostname,
					}

					//auditPayload.IpAuditMap.Set(s, nu)

					// Update the packet count for the interface
					mutex.Lock()
					counts[iface.Name]++
					mutex.Unlock()

					// Print the packet information
					fmt.Println(packetData)
					fmt.Printf("[%s] %s -> %s:%v %s\n", iface.Name, srcAddr, dstAddr, dstPort, hostname)
					//return iface.Name, packet.Data()
				}
			}(iface)
		}
	}
}
