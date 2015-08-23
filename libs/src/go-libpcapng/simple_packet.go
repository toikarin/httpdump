package pcapng

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	PCAPNG_BLOCK_BODY_LEN_SIMPLE_PACKET = 4
)

type SimplePacketBlock struct {
	Block
	PacketLength uint32
	PacketData   []byte
}

func NewSimplePacketBlock(byteOrder binary.ByteOrder, blockHeader *Block, body []byte) (*SimplePacketBlock, error) {
	if len(body) < PCAPNG_BLOCK_BODY_LEN_SIMPLE_PACKET {
		return nil, errors.New(fmt.Sprintf("body requires at least %d bytes of data.", PCAPNG_BLOCK_BODY_LEN_SIMPLE_PACKET))
	}

	return &SimplePacketBlock{
		Block:        *blockHeader,
		PacketLength: byteOrder.Uint32(body[0:4]),
		PacketData:   body[4:],
	}, nil
}
