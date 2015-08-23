package pcapng

type SimplePacketBlock struct {
	totalLength  uint32
	PacketLength uint32
	PacketData   []byte
}

func (SimplePacketBlock) BlockType() uint32 {
	return BLOCK_TYPE_SIMPLE_PACKET
}

func (spb SimplePacketBlock) TotalLength() uint32 {
	return spb.totalLength
}

func (s *Stream) newSimplePacketBlock(body []byte, totalLength uint32) (*SimplePacketBlock, error) {
	return &SimplePacketBlock{
		totalLength:  totalLength,
		PacketLength: s.sectionHeader.ByteOrder.Uint32(body[0:4]),
		PacketData:   body[4:],
	}, nil
}
