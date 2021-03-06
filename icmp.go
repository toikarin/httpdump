package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type ICMPFrame struct {
	Header  *ICMPFrameHeader
	Payload []byte
}

type ICMPFrameHeader struct {
	data []byte
}

const (
	ICMP_FRAME_HEADER_LENGTH = 8
)

func NewICMPFrame(data []byte) (*ICMPFrame, error) {
	header, err := NewICMPFrameHeader(data)
	if err != nil {
		return nil, err
	}

	return &ICMPFrame{header, data[ICMP_FRAME_HEADER_LENGTH:]}, nil
}

func NewICMPFrameHeader(data []byte) (*ICMPFrameHeader, error) {
	if len(data) < ICMP_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", ICMP_FRAME_HEADER_LENGTH))
	}

	return &ICMPFrameHeader{data}, nil
}

func (h ICMPFrameHeader) Type() uint8 {
	return h.data[0]
}

func (h ICMPFrameHeader) Code() uint8 {
	return h.data[1]
}

func (h ICMPFrameHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(h.data[2:4])
}

func (h ICMPFrameHeader) Content() []byte {
	return h.data[4:8]
}
