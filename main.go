package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("failed to read greeting header: %v", err)
		return
	}

	version := header[0]
	nMethods := int(header[1])

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		log.Printf("failed to read methods: %v", err)
		return
	}

	if version != 0x05 {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	requiredMethod := byte(0x00)
	if os.Getenv("PROXY_USER") != "" {
		requiredMethod = 0x02
	}

	methodFound := false
	for _, method := range methods {
		if method == requiredMethod {
			methodFound = true
			break
		}
	}

	if !methodFound {
		conn.Write([]byte{0x05, 0xFF})
		return
	}

	conn.Write([]byte{0x05, requiredMethod})

	if requiredMethod == 0x02 {
		if !authenticateUserPass(conn) {
			return
		}
	}

	target, err := handleConnect(conn)
	if err != nil {
		log.Printf("connect error: %v", err)
		return
	}
	defer target.Close()

	relay(conn, target)
}

func authenticateUserPass(conn net.Conn) bool {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		log.Printf("failed to read auth header: %v", err)
		return false
	}

	version := header[0]
	usernameLen := int(header[1])

	if version != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return false
	}

	username := make([]byte, usernameLen)
	if _, err := io.ReadFull(conn, username); err != nil {
		log.Printf("failed to read username: %v", err)
		return false
	}

	passLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, passLenBuf); err != nil {
		log.Printf("failed to read password length: %v", err)
		return false
	}

	passwordLen := int(passLenBuf[0])
	password := make([]byte, passwordLen)

	if _, err := io.ReadFull(conn, password); err != nil {
		log.Printf("failed to read password: %v", err)
		return false
	}

	if string(username) == os.Getenv("PROXY_USER") &&
		string(password) == os.Getenv("PROXY_PASS") {
		conn.Write([]byte{0x01, 0x00})
		return true
	}

	conn.Write([]byte{0x01, 0x01})
	return false
}

func handleConnect(conn net.Conn) (net.Conn, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	if header[0] != 0x05 {
		sendConnectReply(conn, 0x01)
		return nil, fmt.Errorf("invalid SOCKS version")
	}

	if header[1] != 0x01 {
		sendConnectReply(conn, 0x07)
		return nil, fmt.Errorf("unsupported command")
	}

	if header[2] != 0x00 {
		sendConnectReply(conn, 0x01)
		return nil, fmt.Errorf("invalid reserved byte")
	}

	var host string

	switch header[3] {
	case 0x01:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return nil, err
		}
		host = net.IP(addr).String()

	case 0x03:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, err
		}

		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return nil, err
		}
		host = string(domain)

	default:
		sendConnectReply(conn, 0x08)
		return nil, fmt.Errorf("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return nil, err
	}

	port := binary.BigEndian.Uint16(portBuf)
	targetAddr := fmt.Sprintf("%s:%d", host, port)

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendConnectReply(conn, 0x05)
		return nil, err
	}

	sendConnectReply(conn, 0x00)
	return target, nil
}

func sendConnectReply(conn net.Conn, rep byte) {
	conn.Write([]byte{
		0x05,
		rep,
		0x00,
		0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	})
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)
		if tcp, ok := target.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)
		if tcp, ok := client.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
	}()

	wg.Wait()
}
