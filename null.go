package main

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type NullFrame struct {
	LinkType uint32
	Payload  []byte
}

const (
	NULL_FRAME_HEADER_LENGTH    = 4
	NULL_FRAME_LINKTYPE_AF_INET = 2
)

func NewNullFrame(data []byte, byteOrder binary.ByteOrder) (*NullFrame, error) {
	if len(data) < NULL_FRAME_HEADER_LENGTH {
		return nil, errors.New(fmt.Sprintf("required at least %d bytes of data.", NULL_FRAME_HEADER_LENGTH))
	}

	return &NullFrame{byteOrder.Uint32(data), data[4:]}, nil
}
