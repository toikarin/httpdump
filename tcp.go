package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type TcpFrameHeader struct {
	data []byte
}

const (
	TCP_FRAME_HEADER_LENGTH = 20
	PROTOCOL_ICMP           = 1
	PROTOCOL_TCP            = 6
	PROTOCOL_UDP            = 17
)

func NewTcpFrameHeader(data []byte) (*TcpFrameHeader, error) {
	if len(data) < TCP_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", TCP_FRAME_HEADER_LENGTH))
	}

	return &TcpFrameHeader{data}, nil
}

func (h TcpFrameHeader) SourcePort() uint16 {
	return binary.BigEndian.Uint16(h.data[0:2])
}

func (h TcpFrameHeader) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(h.data[2:4])
}

func (h TcpFrameHeader) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(h.data[4:8])
}

func (h TcpFrameHeader) AcknowledgeNumber() uint32 {
	return binary.BigEndian.Uint32(h.data[8:12])
}

func (h TcpFrameHeader) DataOffset() uint8 {
	return uint8(uint16(h.data[12]>>4) * 32 / 8)
}

func (h TcpFrameHeader) OptionsLength() uint8 {
	return h.DataOffset() - 20
}

func (h TcpFrameHeader) Flags() uint16 {
	return binary.BigEndian.Uint16([]byte{h.data[12] & 0x1, h.data[13]})
}

func (h TcpFrameHeader) FlagNS() bool {
	return h.data[12]&0x1 != 0
}

func (h TcpFrameHeader) FlagCWR() bool {
	return h.data[13]&0x80 != 0
}

func (h TcpFrameHeader) FlagECE() bool {
	return h.data[13]&0x40 != 0
}

func (h TcpFrameHeader) FlagURG() bool {
	return h.data[13]&0x20 != 0
}

func (h TcpFrameHeader) FlagACK() bool {
	return h.data[13]&0x10 != 0
}

func (h TcpFrameHeader) FlagPSH() bool {
	return h.data[13]&0x8 != 0
}

func (h TcpFrameHeader) FlagRST() bool {
	return h.data[13]&0x4 != 0
}

func (h TcpFrameHeader) FlagSYN() bool {
	return h.data[13]&0x2 != 0
}

func (h TcpFrameHeader) FlagFIN() bool {
	return h.data[13]&0x1 != 0
}

func (h TcpFrameHeader) WindowSize() uint16 {
	return binary.BigEndian.Uint16(h.data[14:16])
}

func (h TcpFrameHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(h.data[16:18])
}

func (h TcpFrameHeader) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(h.data[18:20])
}
