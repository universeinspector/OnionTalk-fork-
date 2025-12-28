package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	lenPrefixSize = 4
	nonceSize     = 12
	maxFrameSize  = 1 << 20 // 1 MiB
)

func writeFrame(conn net.Conn, payload []byte) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty payload")
	}
	if len(payload) > maxFrameSize {
		return fmt.Errorf("payload too large: %d", len(payload))
	}

	header := make([]byte, lenPrefixSize)
	binary.BigEndian.PutUint32(header, uint32(len(payload)))

	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(payload)
	return err
}

func readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, lenPrefixSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	n := binary.BigEndian.Uint32(header)
	if n == 0 || n > maxFrameSize {
		return nil, fmt.Errorf("invalid frame size: %d", n)
	}

	payload := make([]byte, n)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
