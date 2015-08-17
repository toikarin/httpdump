package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	IPV6_FRAME_HEADER_LENGTH = 40
)

type IPv6Address [8]uint16

type IPv6Frame struct {
	Header  *IPv6FrameHeader
	Payload []byte
}

type IPv6FrameHeader struct {
	data []byte
}

func NewIPv6Frame(data []byte) (*IPv6Frame, error) {
	header, err := NewIPv6FrameHeader(data)
	if err != nil {
		return nil, err
	}

	if len(data) < int(IPV6_FRAME_HEADER_LENGTH+header.PayloadLength()) {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", IPV6_FRAME_HEADER_LENGTH+header.PayloadLength()))
	}

	return &IPv6Frame{header, data[IPV6_FRAME_HEADER_LENGTH : IPV6_FRAME_HEADER_LENGTH+header.PayloadLength()]}, nil
}

func NewIPv6FrameHeader(data []byte) (*IPv6FrameHeader, error) {
	if len(data) < IPV6_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", IPV6_FRAME_HEADER_LENGTH))
	}

	return &IPv6FrameHeader{data}, nil
}

func (p IPv6FrameHeader) Version() uint8 {
	return uint8(p.data[0] >> 4)
}

func (p IPv6FrameHeader) TrafficClass() uint16 {
	return binary.BigEndian.Uint16([]byte{p.data[0] & 0xF, p.data[1] >> 4})
}

func (p IPv6FrameHeader) FlowControl() uint32 {
	return binary.BigEndian.Uint32([]byte{0, p.data[1] & 0xF, p.data[2], p.data[3]})
}

func (p IPv6FrameHeader) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(p.data[4:6])
}

func (p IPv6FrameHeader) NextHeader() uint8 {
	return p.data[6]
}

func (p IPv6FrameHeader) Protocol() uint8 {
	return p.NextHeader()
}

func (p IPv6FrameHeader) HopLimit() uint8 {
	return p.data[7]
}

func (p IPv6FrameHeader) SourceAddress() IPv6Address {
	return IPv6Address{
		binary.BigEndian.Uint16(p.data[8:10]),
		binary.BigEndian.Uint16(p.data[10:12]),
		binary.BigEndian.Uint16(p.data[12:14]),
		binary.BigEndian.Uint16(p.data[14:16]),
		binary.BigEndian.Uint16(p.data[16:18]),
		binary.BigEndian.Uint16(p.data[18:20]),
		binary.BigEndian.Uint16(p.data[20:22]),
		binary.BigEndian.Uint16(p.data[22:24]),
	}
}

func (p IPv6FrameHeader) DestinationAddress() IPv6Address {
	return IPv6Address{
		binary.BigEndian.Uint16(p.data[24:26]),
		binary.BigEndian.Uint16(p.data[26:28]),
		binary.BigEndian.Uint16(p.data[28:30]),
		binary.BigEndian.Uint16(p.data[30:32]),
		binary.BigEndian.Uint16(p.data[32:34]),
		binary.BigEndian.Uint16(p.data[34:36]),
		binary.BigEndian.Uint16(p.data[36:38]),
		binary.BigEndian.Uint16(p.data[38:40]),
	}
}
