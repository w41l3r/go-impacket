package relay

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

// ListenSOCKS5 starts a SOCKS5 proxy server (RFC 1928, no-auth, CONNECT only).
// Each accepted connection is handled in a goroutine; cancelling ctx closes the listener.
func ListenSOCKS5(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("SOCKS5 listen %s: %w", addr, err)
	}
	log.Printf("[refract] SOCKS5 proxy on %s", addr)
	defer ln.Close()

	go func() { <-ctx.Done(); ln.Close() }()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[refract] SOCKS5 accept: %v", err)
				continue
			}
		}
		go handleSOCKS5Client(conn)
	}
}

func handleSOCKS5Client(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(30 * time.Second))

	if err := socks5AuthHandshake(client); err != nil {
		log.Printf("[refract] SOCKS5 auth: %v", err)
		return
	}

	target, err := socks5ReadConnect(client)
	if err != nil {
		log.Printf("[refract] SOCKS5 request: %v", err)
		socks5Reply(client, 0x01, nil) // general failure
		return
	}

	remote, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		log.Printf("[refract] SOCKS5 connect %s: %v", target, err)
		code := byte(0x05) // connection refused
		if isHostUnreachable(err) {
			code = 0x04
		}
		socks5Reply(client, code, nil)
		return
	}
	defer remote.Close()

	if err := socks5Reply(client, 0x00, remote.LocalAddr()); err != nil {
		return
	}

	// Clear deadline; proxy runs until one side closes.
	client.SetDeadline(time.Time{})
	remote.SetDeadline(time.Time{})

	log.Printf("[refract] SOCKS5 → %s", target)
	socks5Proxy(client, remote)
}

// socks5AuthHandshake handles the method-negotiation phase.
// We only support no-auth (0x00); we reply with method=0xFF if the client
// doesn't offer it, closing the connection naturally.
func socks5AuthHandshake(c net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return err
	}
	if hdr[0] != 5 {
		return fmt.Errorf("not SOCKS5 (version=%d)", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == 0x00 {
			_, err := c.Write([]byte{0x05, 0x00})
			return err
		}
	}
	c.Write([]byte{0x05, 0xFF}) // no acceptable method
	return fmt.Errorf("client offered no supported auth methods")
}

// socks5ReadConnect reads the CONNECT request and returns the target address.
func socks5ReadConnect(c net.Conn) (string, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return "", err
	}
	if hdr[0] != 5 {
		return "", fmt.Errorf("bad SOCKS5 version in request: %d", hdr[0])
	}
	if hdr[1] != 0x01 {
		socks5Reply(c, 0x07, nil) // command not supported
		return "", fmt.Errorf("unsupported SOCKS5 command: 0x%02x", hdr[1])
	}

	var host string
	switch hdr[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03: // domain name
		nb := make([]byte, 1)
		if _, err := io.ReadFull(c, nb); err != nil {
			return "", err
		}
		dom := make([]byte, nb[0])
		if _, err := io.ReadFull(c, dom); err != nil {
			return "", err
		}
		host = string(dom)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		socks5Reply(c, 0x08, nil) // address type not supported
		return "", fmt.Errorf("unsupported ATYP: 0x%02x", hdr[3])
	}

	pb := make([]byte, 2)
	if _, err := io.ReadFull(c, pb); err != nil {
		return "", err
	}
	port := binary.BigEndian.Uint16(pb)
	return net.JoinHostPort(host, fmt.Sprintf("%d", port)), nil
}

// socks5Reply sends a SOCKS5 response with the given reply code and bound address.
func socks5Reply(c net.Conn, rep byte, bindAddr net.Addr) error {
	var ip net.IP
	var port uint16
	if bindAddr != nil {
		if tcp, ok := bindAddr.(*net.TCPAddr); ok {
			ip = tcp.IP
			port = uint16(tcp.Port)
		}
	}

	var reply []byte
	switch {
	case len(ip) == 4:
		reply = append([]byte{0x05, rep, 0x00, 0x01}, ip...)
	case len(ip) == 16:
		reply = append([]byte{0x05, rep, 0x00, 0x04}, ip...)
	default:
		reply = []byte{0x05, rep, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	}
	pb := make([]byte, 2)
	binary.BigEndian.PutUint16(pb, port)
	reply = append(reply, pb...)

	_, err := c.Write(reply)
	return err
}

func socks5Proxy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(b, a); b.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	go func() { io.Copy(a, b); a.(*net.TCPConn).CloseWrite(); done <- struct{}{} }()
	<-done
	<-done
}

func isHostUnreachable(err error) bool {
	if ne, ok := err.(*net.OpError); ok {
		return ne.Timeout()
	}
	return false
}
