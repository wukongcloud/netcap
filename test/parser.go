package test

import (
	"bufio"
	"bytes"
	"net/http"
)

const (
	acc_proto_udp = iota + 1
	acc_proto_tcp
	acc_proto_https
	acc_proto_http
)


var TcpParsers = []func([]byte) (uint8, string){
	SniNewParser,
	HttpParser,
}

func HttpParser(data []byte) (uint8, string) {
	if req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data))); err == nil {
		return acc_proto_http, req.Host
	}
	return acc_proto_tcp, ""
}

func SniNewParser(b []byte) (protocol uint8, hostname string) {
	if len(b) < 2 || b[0] != 0x16 || b[1] != 0x03 {
		return acc_proto_tcp, ""
	}
	rest := b[5:]
	restLen := len(rest)
	if restLen == 0 {
		return acc_proto_tcp, ""
	}
	current := 0
	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		return acc_proto_tcp, ""
	}
	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	if current >= restLen {
		return acc_proto_https, ""
	}
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength
	if current+1 >= restLen {
		return acc_proto_https, ""
	}
	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength
	if current >= restLen {
		return acc_proto_https, ""
	}
	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current >= restLen {
		return acc_proto_https, ""
	}
	current += 2
	for current+4 < restLen && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2
		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2
		if extensionType == 0 {
			// Skip over number of names as we're assuming there's just one
			current += 2
			if current >= restLen {
				return acc_proto_https, ""
			}
			nameType := rest[current]
			current += 1
			if nameType != 0 {
				return acc_proto_https, ""
			}
			if current+1 >= restLen {
				return acc_proto_https, ""
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			if current+nameLen >= restLen {
				return acc_proto_https, ""
			}
			hostname = string(rest[current : current+nameLen])
		}
		current += extensionDataLength
	}
	if hostname == "" {
		return acc_proto_https, ""
	}
	if !validDomainChar(hostname) {
		return acc_proto_https, ""
	}
	return acc_proto_https, hostname
}

// 校验域名的合法字符, 处理乱码问题
func validDomainChar(addr string) bool {
	// Allow a-z A-Z . - 0-9
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		if !((c >= 97 && c <= 122) || (c >= 65 && c <= 90) || (c >= 45 && c <= 46) || (c >= 48 && c <= 57)) {
			return false
		}
	}
	return true
}
