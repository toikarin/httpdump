package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	IPV4_FRAME_HEADER_LENGTH = 20
)

type IPv4FrameHeader struct {
	data []byte
}

func NewIPv4FrameHeader(data []byte) (*IPv4FrameHeader, error) {
	if len(data) < IPV4_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", IPV4_FRAME_HEADER_LENGTH))
	}

	return &IPv4FrameHeader{data}, nil
}

func (p IPv4FrameHeader) Version() uint8 {
	return uint8(p.data[0] >> 4)
}

func (p IPv4FrameHeader) HeaderLength() uint8 {
	return (p.data[0] & 0xf) * 32 / 8
}

func (p IPv4FrameHeader) DSCP() uint8 {
	return (p.data[1] >> 2)
}

func (p IPv4FrameHeader) ECN() uint8 {
	return p.data[1] & 0x3
}

func (p IPv4FrameHeader) TotalLength() uint16 {
	return binary.BigEndian.Uint16(p.data[2:4])
}

func (p IPv4FrameHeader) Identification() uint16 {
	return binary.BigEndian.Uint16(p.data[4:6])
}

func (p IPv4FrameHeader) Flags() uint8 {
	return p.data[6] >> 5
}

func (p IPv4FrameHeader) DontFragment() bool {
	return p.Flags()&0x2 != 0
}

func (p IPv4FrameHeader) MoreFragments() bool {
	return p.Flags()&0x1 != 0
}

func (p IPv4FrameHeader) FragmentOffset() uint16 {
	return binary.BigEndian.Uint16([]byte{p.data[6] & 0x1F, p.data[7]})
}

func (p IPv4FrameHeader) TimeToLive() uint8 {
	return p.data[8]
}

func (p IPv4FrameHeader) Protocol() uint8 {
	return p.data[9]
}

func (p IPv4FrameHeader) HeaderChecksum() uint16 {
	return binary.BigEndian.Uint16(p.data[10:12])
}

func (p IPv4FrameHeader) SourceAddress() uint32 {
	return binary.BigEndian.Uint32(p.data[12:16])
}

func (p IPv4FrameHeader) DestinationAddress() uint32 {
	return binary.BigEndian.Uint32(p.data[16:20])
}
