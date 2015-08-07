package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type UDPFrameHeader struct {
	data []byte
}

const (
	UDP_FRAME_HEADER_LENGTH = 8
)

func NewUDPFrameHeader(data []byte) (*UDPFrameHeader, error) {
	if len(data) < UDP_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", UDP_FRAME_HEADER_LENGTH))
	}

	return &UDPFrameHeader{data}, nil
}

func (h UDPFrameHeader) SourcePort() uint16 {
	return binary.BigEndian.Uint16(h.data[0:2])
}

func (h UDPFrameHeader) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(h.data[2:4])
}

func (h UDPFrameHeader) Length() uint16 {
	return binary.BigEndian.Uint16(h.data[4:6])
}

func (h UDPFrameHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(h.data[6:8])
}
