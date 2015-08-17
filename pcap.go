package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	PCAP_FILE_HEADER_LENGTH   = 24
	PCAP_PACKET_HEADER_LENGTH = 16
)

var INVALID_FILETYPE = errors.New("invalid magic number")

type PcapFileHeader struct {
	ByteOrder binary.ByteOrder
	data      []byte
}

type PcapPacketHeader struct {
	data []byte
	bo   binary.ByteOrder
}

func (h PcapFileHeader) VersionMajor() uint16 {
	return h.ByteOrder.Uint16(h.data[4:6])
}

func (h PcapFileHeader) VersionMinor() uint16 {
	return h.ByteOrder.Uint16(h.data[6:8])
}

func (h PcapFileHeader) ThisZone() int32 {
	return int32(h.ByteOrder.Uint32(h.data[8:12]))
}

func (h PcapFileHeader) Sigfigs() uint32 {
	return h.ByteOrder.Uint32(h.data[12:16])
}

func (h PcapFileHeader) SnapLength() uint32 {
	return h.ByteOrder.Uint32(h.data[16:20])
}

func (h PcapFileHeader) Network() uint32 {
	return h.ByteOrder.Uint32(h.data[20:24])
}

func (p PcapPacketHeader) Timestamp() time.Time {
	tsSecs := p.bo.Uint32(p.data[0:4])
	tsMicrosecs := p.bo.Uint32(p.data[4:8])
	return time.Unix(int64(tsSecs), int64(tsMicrosecs)*1000)
}

func (p PcapPacketHeader) IncludeLength() uint32 {
	return p.bo.Uint32(p.data[8:12])
}

func (p PcapPacketHeader) OriginalLength() uint32 {
	return p.bo.Uint32(p.data[12:16])
}

func NewPcapPacketHeader(data []byte, bo binary.ByteOrder) (*PcapPacketHeader, error) {
	if len(data) < PCAP_PACKET_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", PCAP_PACKET_HEADER_LENGTH))
	}

	return &PcapPacketHeader{
		data: data,
		bo:   bo,
	}, nil
}

func NewPcapFileHeader(data []byte) (header *PcapFileHeader, err error) {
	if len(data) < PCAP_FILE_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", PCAP_FILE_HEADER_LENGTH))
	}

	var bo binary.ByteOrder

	if data[0] == 0xA1 && data[1] == 0xB2 && data[2] == 0xC3 && data[3] == 0xD4 {
		bo = binary.BigEndian
	} else if data[3] == 0xA1 && data[2] == 0xB2 && data[1] == 0xC3 && data[0] == 0xD4 {
		bo = binary.LittleEndian
	} else {
		return nil, INVALID_FILETYPE
	}

	return &PcapFileHeader{
		ByteOrder: bo,
		data:      data,
	}, nil
}
