package utils

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/songgao/water/waterutil"
)

// 解析IP包的数据
func LogAudit(pl []byte) {
	ipProto := waterutil.IPv4Protocol(pl)
	// 访问协议
	var accessProto uint8
	// 只统计 tcp和udp 的访问
	switch ipProto {
	case waterutil.TCP:
		accessProto = acc_proto_tcp
	case waterutil.UDP:
		accessProto = acc_proto_udp
	default:
		return
	}

	ipSrc := waterutil.IPv4Source(pl)
	ipDst := waterutil.IPv4Destination(pl)
	ipPort := waterutil.IPv4DestinationPort(pl)

	b := getByte51()
	key := *b
	copy(key[:16], ipSrc)
	copy(key[16:32], ipDst)
	binary.BigEndian.PutUint16(key[32:34], ipPort)

	info := ""
	//nu := utils.NowSec().Unix()
	if ipProto == waterutil.TCP {
		plData := waterutil.IPv4Payload(pl)
		if len(plData) < 14 {
			return
		}
		flags := plData[13]
		switch flags {
		case flags & 0x20:
			// URG
			return
		case flags & 0x14:
			// RST ACK
			return
		case flags & 0x12:
			// SYN ACK
			return
		case flags & 0x11:
			// Client FIN
			return
		case flags & 0x10:
			// ACK
			return
		case flags & 0x08:
			// PSH
			return
		case flags & 0x04:
			// RST
			return
		case flags & 0x02:
			// SYN
			return
		case flags & 0x01:
			// FIN
			return
		case flags & 0x18:
			// PSH ACK
			accessProto, info = onTCP(plData)
			if info != "" {
				// 提前存储只含ip数据的key, 避免即记录域名又记录一笔IP数据的记录
				ipKey := make([]byte, 51)
				copy(ipKey, key)
				//ipS := utils.BytesToString(ipKey)
				//cSess.IpAuditMap.Set(ipS, nu)
				// 存储含域名的key
				key[34] = byte(accessProto)
				md5Sum := md5.Sum([]byte(info))
				copy(key[35:51], hex.EncodeToString(md5Sum[:]))
			}
			fmt.Println(info,"\n\n\n\n\n")
		case flags & 0x19:
			// URG
			return
		case flags & 0xC2:
			// SYN-ECE-CWR
			return
		}
	}
	//s := utils.BytesToString(key)

	// 判断已经存在，并且没有过期
	//v, ok := cSess.IpAuditMap.Get(s)
	//if ok && nu-v.(int64) < int64(base.Cfg.AuditInterval) {
	//	// 回收byte对象
	//	putByte51(b)
	return
}

//cSess.IpAuditMap.Set(s, nu)

//audit := dbdata.AccessAudit{
//	Username:    cSess.Username,
//	Protocol:    uint8(ipProto),
//	Src:         ipSrc.String(),
//	Dst:         ipDst.String(),
//	DstPort:     ipPort,
//	CreatedAt:   utils.NowSec(),
//	AccessProto: accessProto,
//	Info:        info,
//}
//logAuditWrite(audit)

//}
