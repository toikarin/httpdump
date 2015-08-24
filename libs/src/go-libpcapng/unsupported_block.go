package pcapng

type UnsupportedBlock struct {
	blockType   uint32
	totalLength uint32
	Data        []byte
}

func (us UnsupportedBlock) BlockType() uint32 {
	return us.blockType
}

func (us UnsupportedBlock) TotalLength() uint32 {
	return us.totalLength
}

func (s *Stream) newUnsupportedBlock(body []byte, blockType, totalLength uint32) (*UnsupportedBlock, error) {
	return &UnsupportedBlock{
		blockType:   blockType,
		totalLength: totalLength,
		Data:        body,
	}, nil
}
