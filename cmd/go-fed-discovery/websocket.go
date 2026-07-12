package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

func acceptWebSocket(listener net.Listener, fixture Fixture, trusted map[string]map[string]any) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleWebSocket(conn, fixture, trusted)
	}
}

func handleWebSocket(conn net.Conn, fixture Fixture, trusted map[string]map[string]any) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	if err := websocketHandshake(conn, reader); err != nil {
		return
	}
	session := &Session{}
	sendWS := func(frame map[string]any) {
		data, _ := json.Marshal(frame)
		_ = writeWebSocketText(conn, string(data))
	}
	for {
		text, err := readWebSocketText(reader)
		if err != nil {
			return
		}
		var frame map[string]any
		if err := json.Unmarshal([]byte(text), &frame); err != nil {
			sendWS(taskErrorFrame(err))
			return
		}
		if !handleFrameBytes(sendWS, []byte(text), frame, fixture, trusted, session) {
			return
		}
	}
}

func websocketHandshake(conn net.Conn, reader *bufio.Reader) error {
	headers := map[string]string{}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if index := strings.Index(line, ":"); index >= 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:index]))] = strings.TrimSpace(line[index+1:])
		}
	}
	key := headers["sec-websocket-key"]
	if key == "" {
		return errors.New("missing sec-websocket-key")
	}
	hash := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	accept := base64.StdEncoding.EncodeToString(hash[:])
	_, err := fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", accept)
	return err
}

func readWebSocketText(reader *bufio.Reader) (string, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	second, err := reader.ReadByte()
	if err != nil {
		return "", err
	}
	opcode := first & 0x0f
	if opcode == 0x8 {
		return "", io.EOF
	}
	if opcode != 0x1 {
		return "", errors.New("expected websocket text frame")
	}
	masked := second&0x80 != 0
	length := uint64(second & 0x7f)
	if length == 126 {
		var buf [2]byte
		if _, err := io.ReadFull(reader, buf[:]); err != nil {
			return "", err
		}
		length = uint64(binary.BigEndian.Uint16(buf[:]))
	} else if length == 127 {
		var buf [8]byte
		if _, err := io.ReadFull(reader, buf[:]); err != nil {
			return "", err
		}
		length = binary.BigEndian.Uint64(buf[:])
	}
	if length > uint64(maxSwarmOutputVerificationFrameBytes) {
		return "", errors.New("websocket frame exceeds maximum size")
	}
	var mask [4]byte
	if masked {
		if _, err := io.ReadFull(reader, mask[:]); err != nil {
			return "", err
		}
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return "", err
	}
	if masked {
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	return string(payload), nil
}

func writeWebSocketText(conn net.Conn, text string) error {
	payload := []byte(text)
	header := []byte{0x81}
	switch {
	case len(payload) < 126:
		header = append(header, byte(len(payload)))
	case len(payload) <= 0xffff:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127, 0, 0, 0, 0, byte(len(payload)>>24), byte(len(payload)>>16), byte(len(payload)>>8), byte(len(payload)))
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}
