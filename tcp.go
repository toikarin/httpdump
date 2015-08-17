package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type TCPFrame struct {
	Header  *TCPFrameHeader
	Options []byte
	Payload []byte
}

type TCPFrameHeader struct {
	data []byte
}

const (
	TCP_FRAME_HEADER_LENGTH = 20
)

func NewTCPFrame(data []byte) (*TCPFrame, error) {
	//
	// Read TCP header
	//
	header, err := NewTCPFrameHeader(data)
	if err != nil {
		return nil, err
	}

	if len(data) < int(header.DataOffset()) {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", header.DataOffset()))
	}

	//
	// Read TCP options
	//
	optsLen := header.OptionsLength()
	var opts []byte
	if optsLen > 0 {
		opts = data[optsLen:]
	} else {
		opts = nil
	}

	return &TCPFrame{header, opts, data[header.DataOffset():]}, nil
}

func NewTCPFrameHeader(data []byte) (*TCPFrameHeader, error) {
	if len(data) < TCP_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", TCP_FRAME_HEADER_LENGTH))
	}

	return &TCPFrameHeader{data}, nil
}

func (h TCPFrameHeader) SourcePort() uint16 {
	return binary.BigEndian.Uint16(h.data[0:2])
}

func (h TCPFrameHeader) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(h.data[2:4])
}

func (h TCPFrameHeader) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(h.data[4:8])
}

func (h TCPFrameHeader) AcknowledgeNumber() uint32 {
	return binary.BigEndian.Uint32(h.data[8:12])
}

func (h TCPFrameHeader) DataOffset() uint8 {
	return uint8(uint16(h.data[12]>>4) * 32 / 8)
}

func (h TCPFrameHeader) OptionsLength() uint8 {
	return h.DataOffset() - 20
}

func (h TCPFrameHeader) Flags() uint16 {
	return binary.BigEndian.Uint16([]byte{h.data[12] & 0x1, h.data[13]})
}

func (h TCPFrameHeader) FlagNS() bool {
	return h.data[12]&0x1 != 0
}

func (h TCPFrameHeader) FlagCWR() bool {
	return h.data[13]&0x80 != 0
}

func (h TCPFrameHeader) FlagECE() bool {
	return h.data[13]&0x40 != 0
}

func (h TCPFrameHeader) FlagURG() bool {
	return h.data[13]&0x20 != 0
}

func (h TCPFrameHeader) FlagACK() bool {
	return h.data[13]&0x10 != 0
}

func (h TCPFrameHeader) FlagPSH() bool {
	return h.data[13]&0x8 != 0
}

func (h TCPFrameHeader) FlagRST() bool {
	return h.data[13]&0x4 != 0
}

func (h TCPFrameHeader) FlagSYN() bool {
	return h.data[13]&0x2 != 0
}

func (h TCPFrameHeader) FlagFIN() bool {
	return h.data[13]&0x1 != 0
}

func (h TCPFrameHeader) WindowSize() uint16 {
	return binary.BigEndian.Uint16(h.data[14:16])
}

func (h TCPFrameHeader) Checksum() uint16 {
	return binary.BigEndian.Uint16(h.data[16:18])
}

func (h TCPFrameHeader) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(h.data[18:20])
}
