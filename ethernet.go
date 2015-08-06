package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type EthernetFrameHeader struct {
	data []byte
}

const (
	ETHERNET_FRAME_HEADER_LENGTH = 14
	ETHERTYPE_IPV4               = 0x800
	ETHERTYPE_IPV6               = 0x86DD
)

func NewEthernetFrameHeader(data []byte) (*EthernetFrameHeader, error) {
	if len(data) < ETHERNET_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", ETHERNET_FRAME_HEADER_LENGTH))
	}

	return &EthernetFrameHeader{data}, nil
}

func (h EthernetFrameHeader) Destination() []byte {
	return h.data[0:6]
}

func (h EthernetFrameHeader) Source() []byte {
	return h.data[6:12]
}

func (h EthernetFrameHeader) Type() uint16 {
	return binary.BigEndian.Uint16(h.data[12:14])
}
