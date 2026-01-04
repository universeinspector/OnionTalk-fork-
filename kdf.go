package main

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const protocolInfo = "oniontalk-v1"

func deriveKey(sharedSecret []byte, info string) ([]byte, error) {
	h := hkdf.New(sha256.New, sharedSecret, nil, []byte(info))

	key := make([]byte, 32) // AES-256
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}

func deriveDirectionalKeys(sharedSecret []byte) (c2s []byte, s2c []byte, err error) {
	c2s, err = deriveKey(sharedSecret, protocolInfo+"|c2s")
	if err != nil {
		return nil, nil, err
	}
	s2c, err = deriveKey(sharedSecret, protocolInfo+"|s2c")
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}
