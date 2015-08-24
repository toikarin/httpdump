package pcap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	FILE_HEADER_LENGTH   = 24
	PACKET_HEADER_LENGTH = 16

	LINKTYPE_NULL     = 0
	LINKTYPE_ETHERNET = 1
)

var INVALID_FILETYPE = errors.New("invalid magic number")

type FileHeader struct {
	ByteOrder binary.ByteOrder
	data      []byte
}

type PacketHeader struct {
	data []byte
	bo   binary.ByteOrder
}

func (h FileHeader) VersionMajor() uint16 {
	return h.ByteOrder.Uint16(h.data[4:6])
}

func (h FileHeader) VersionMinor() uint16 {
	return h.ByteOrder.Uint16(h.data[6:8])
}

func (h FileHeader) ThisZone() int32 {
	return int32(h.ByteOrder.Uint32(h.data[8:12]))
}

func (h FileHeader) Sigfigs() uint32 {
	return h.ByteOrder.Uint32(h.data[12:16])
}

func (h FileHeader) SnapLength() uint32 {
	return h.ByteOrder.Uint32(h.data[16:20])
}

func (h FileHeader) Network() uint32 {
	return h.ByteOrder.Uint32(h.data[20:24])
}

func (p PacketHeader) Timestamp() time.Time {
	tsSecs := p.bo.Uint32(p.data[0:4])
	tsMicrosecs := p.bo.Uint32(p.data[4:8])
	return time.Unix(int64(tsSecs), int64(tsMicrosecs)*1000)
}

func (p PacketHeader) IncludeLength() uint32 {
	return p.bo.Uint32(p.data[8:12])
}

func (p PacketHeader) OriginalLength() uint32 {
	return p.bo.Uint32(p.data[12:16])
}

func NewPacketHeader(data []byte, bo binary.ByteOrder) (*PacketHeader, error) {
	if len(data) < PACKET_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", PACKET_HEADER_LENGTH))
	}

	return &PacketHeader{
		data: data,
		bo:   bo,
	}, nil
}

func NewFileHeader(data []byte) (header *FileHeader, err error) {
	if len(data) < FILE_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", FILE_HEADER_LENGTH))
	}

	var bo binary.ByteOrder

	if data[0] == 0xA1 && data[1] == 0xB2 && data[2] == 0xC3 && data[3] == 0xD4 {
		bo = binary.BigEndian
	} else if data[3] == 0xA1 && data[2] == 0xB2 && data[1] == 0xC3 && data[0] == 0xD4 {
		bo = binary.LittleEndian
	} else {
		return nil, INVALID_FILETYPE
	}

	return &FileHeader{
		ByteOrder: bo,
		data:      data,
	}, nil
}

func IsPcapStream(data []byte) bool {
	return (data[0] == 0xa1 && data[1] == 0xb2 && data[2] == 0xc3 && data[3] == 0xd4) ||
		(data[3] == 0xa1 && data[2] == 0xb2 && data[1] == 0xc3 && data[0] == 0xd4)
}
