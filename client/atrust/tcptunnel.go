package atrust

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

func calcXRequestSig(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	sum := h.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(sum))
}

func (c *Client) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	appID := ""
	nodeGroupID := ""
	domain := ""
	if res := ctx.Value(resolve.ContextKeyDomainResource); res != nil {
		resource := res.(client.DomainResource)
		appID = resource.AppID
		nodeGroupID = resource.NodeGroupID
		if res = ctx.Value(resolve.ContextKeyResolveHost); res != nil {
			domain = res.(string)
		}
	} else {
		for _, resource := range c.ipResources {
			if bytes.Compare(addr.IP, resource.IPMin) >= 0 && bytes.Compare(addr.IP, resource.IPMax) <= 0 {
				if resource.PortMin <= addr.Port && addr.Port <= resource.PortMax {
					if resource.Protocol == "tcp" || resource.Protocol == "all" {
						appID = resource.AppID
						nodeGroupID = resource.NodeGroupID
					}
				}
			}
		}
	}

	c.BestNodesRWMutex.RLock()
	nodeAddr := c.BestNodes[nodeGroupID]
	if nodeAddr == "" {
		nodeAddr = c.BestNodes[c.MajorNodeGroup]
	}
	c.BestNodesRWMutex.RUnlock()
	if nodeAddr == "" {
		return nil, fmt.Errorf("no available aTrust node for group %q", nodeGroupID)
	}
	conn, err := tls.Dial("tcp", nodeAddr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to aTrust server: %w", err)
	}
	procName := "google-chrome-stable"
	procPath := "/usr/bin/google-chrome-stable"
	if addr.Port == 22 {
		procName = "ssh"
		procPath = "/usr/bin/ssh"
	}
	procHash := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))

	destAddr := addr.String()
	if domain != "" {
		destAddr = fmt.Sprintf("%s:%d", domain, addr.Port)
	}

	destIP := addr.IP.To4()
	if destIP == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	destPort := make([]byte, 2)
	binary.BigEndian.PutUint16(destPort, uint16(addr.Port))

	msg := fmt.Sprintf(
		`{"sid":"%s","appId":"%s","url":"tcp://%s","deviceId":"%s","connectionId":"%s","procHash":"%s","userName":"%s","rcAppliedInfo":0,"lang":"en-US","destAddr":"%s","env":{"application":{"runtime":{"process":{"name":"%s","digital_signature":"TrustAppClosed","platform":"Linux","fingerprint":"%s","description":"TrustAppClosed","path":"%s","version":"TrustAppClosed","security_env":"normal"},"process_trusted":"TRUSTED"}}},"xRequestSig":""}`,
		c.SID, appID, destAddr, c.DeviceID, c.ConnectionID, procHash, c.Username, destAddr, procName, procHash, procPath,
	)
	signKeyBytes, err := hex.DecodeString(c.SignKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}

	sig := calcXRequestSig(signKeyBytes, []byte(msg))
	msg = msg[:len(msg)-3] + `"` + sig + `"}`
	msgBytes := []byte(msg)
	msgLen := len(msgBytes)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(msgLen))
	initHeader := []byte{0x05, 0x01, 0x81, 0x53, 0x03}
	initMsg := append(initHeader, lenBytes...)
	initMsg = append(initMsg, msgBytes...)
	if _, err := conn.Write(initMsg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to send init message: %w", err)
	}
	log.DebugDumpHex(initMsg)

	var destMsg []byte
	if domain == "" {
		destHeader := []byte{0x05, 0x01, 0x01, 0x01}
		destMsg = append(destHeader, destIP...)
	} else {
		destHeader := []byte{0x05, 0x01, 0x01, 0x03}
		// For domain, we need to send the length of the domain name
		domainLen := len(domain)
		if domainLen > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("domain name too long: %s", domain)
		}
		destHeader = append(destHeader, byte(domainLen))
		destMsg = append(destHeader, []byte(domain)...)
	}
	destMsg = append(destMsg, destPort...)
	if _, err := conn.Write(destMsg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to send dest address: %w", err)
	}
	log.DebugDumpHex(destMsg)

	// =====================================================================
	// 优雅且严谨地读取握手响应，不使用任何缓冲，绝对避免误吞真实业务流量
	// =====================================================================

	header2 := make([]byte, 2)
	if _, err := io.ReadFull(conn, header2); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to read handshake response: %w", err)
	}

	// 1. 如果服务器先返回了 aTrust 专有的身份确认 JSON (05 81 开头)
	if header2[0] == 0x05 && header2[1] == 0x81 {
		buf4 := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf4); err == nil {
			if buf4[0] == 0x53 && buf4[1] == 0x00 { // 53 00 + 2字节长度
				msgLen := binary.BigEndian.Uint16(buf4[2:4])
				jsonData := make([]byte, msgLen)
				io.ReadFull(conn, jsonData)
				log.DebugPrint("aTrust Handshake Info: ", string(jsonData))
			}
		}

		// 消费完 JSON 后，紧接着读下 2 个字节，此时才迎来真实的 SOCKS5 响应头
		if _, err := io.ReadFull(conn, header2); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("failed to read SOCKS5 reply: %w", err)
		}
	}

	// 2. 此时 header2 必须是标准 SOCKS5 成功响应: 05 00
	if header2[0] != 0x05 || header2[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("SOCKS5 connection rejected, rep code: %x", header2[1])
	}

	// 3. 读取保留字段 (RSV) 和地址类型 (ATYP)
	atypBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, atypBuf); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to read SOCKS5 ATYP: %w", err)
	}

	// 4. 根据 ATYP 动态且精准地消耗剩余的数据 (绝不多读 1 个字节)
	switch atypBuf[1] {
	case 0x01: // IPv4 (4字节 IP + 2字节 Port)
		io.ReadFull(conn, make([]byte, 6))
	case 0x03: // Domain (1字节长度 + 域名 + 2字节 Port)
		domainLen := make([]byte, 1)
		io.ReadFull(conn, domainLen)
		io.ReadFull(conn, make([]byte, int(domainLen[0])+2))
	case 0x04: // IPv6 (16字节 IP + 2字节 Port)
		io.ReadFull(conn, make([]byte, 18))
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("unknown SOCKS5 atyp: %x", atypBuf[1])
	}

	// 握手干净利落地完成，底层的 tls.Conn 就是最完美、无多余封装的净透隧道
	return conn, nil
}
