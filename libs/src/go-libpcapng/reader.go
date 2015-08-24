package pcapng

import (
	"io"
)

type Stream struct {
	r             io.Reader
	sectionHeader *SectionHeaderBlock
	interfaces    []*InterfaceDescriptionBlock
}

func NewStream(r io.Reader) *Stream {
	return &Stream{
		r:             r,
		sectionHeader: nil,
		interfaces:    make([]*InterfaceDescriptionBlock, 0),
	}
}

func (s *Stream) NextBlock() (Block, error) {
	//
	// Read initial section header
	//
	if s.sectionHeader == nil {
		return s.readSectionHeaderBlock()
	}

	//
	// Read block header
	//
	headerBuf, err := s.read(8)
	if err != nil {

		return nil, err
	}

	//
	// special case for section header
	//
	if headerBuf[0] == 0x0A && headerBuf[1] == 0x0D && headerBuf[2] == 0x0D && headerBuf[3] == 0x0A {
		return s.readSectionHeaderBlockBody(headerBuf)
	}

	blockType := s.sectionHeader.ByteOrder.Uint32(headerBuf[0:4])
	totalLength := s.sectionHeader.ByteOrder.Uint32(headerBuf[4:8])

	//
	// Read body
	//
	bodyData, err := s.readExactly(totalLength - 12)
	if err != nil {
		return nil, err
	}

	//
	// read last total length
	//
	footerBuf, err := s.readExactly(4)
	if err != nil {
		return nil, err
	}

	//
	// make sure footer length equals to header length
	//
	totalLenFooter := s.sectionHeader.ByteOrder.Uint32(footerBuf[0:4])
	if totalLenFooter != totalLength {
		return nil, PCAPNG_CORRUPTED_FILE
	}

	switch blockType {
	case BLOCK_TYPE_PACKET:
		return s.newPacketBlock(bodyData, totalLength)
	case BLOCK_TYPE_SIMPLE_PACKET:
		return s.newSimplePacketBlock(bodyData, totalLength)
	case BLOCK_TYPE_ENHANCED_PACKET:
		return s.newEnhancedPacketBlock(bodyData, totalLength)
	case BLOCK_TYPE_INTERFACE_DESC:
		ifdb, err := s.newInterfaceDescriptionBlock(bodyData, totalLength)
		s.interfaces = append(s.interfaces, ifdb)

		return ifdb, err
	case BLOCK_TYPE_EXPERIMENTAL_PROCESS_INFORMATION:
		return s.newProcessInformationBlock(bodyData, totalLength)
	case BLOCK_TYPE_INTERFACE_STATS:
		return s.newInterfaceStatisticsBlock(bodyData, totalLength)
	case BLOCK_TYPE_NAME_RESOLUTION:
		return s.newNameResolutionBlock(bodyData, totalLength)
	case BLOCK_TYPE_SECTION_HEADER:
		//
		// this is handled before the switch case
		//
		panic("should not be here")
	default:
		return s.newUnsupportedBlock(bodyData, blockType, totalLength)
	}
}

func (s *Stream) SkipSection() error {
	if !s.sectionHeader.SupportsSkipping() {
		return PCAPNG_SKIPPING_NOT_SUPPORTED
	}

	s.readExactlyInt64(s.sectionHeader.SectionLength)

	return nil
}

//
// internal funcs
//

func (s *Stream) readOptions(optsLen uint32) (*RawOptions, error) {
	optsLen = alignUint32(optsLen)

	if optsLen > 0 {
		buf, err := s.readExactly(optsLen)
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}

			return nil, err
		}

		return s.parseOptions(buf)
	}

	return nil, nil
}

func (s *Stream) read(n uint32) (buf []byte, err error) {
	return s.readInt64(int64(n))
}

func (s *Stream) readExactly(n uint32) (buf []byte, err error) {
	return s.readExactlyInt64(int64(n))
}

func (s *Stream) readInt64(n int64) (buf []byte, err error) {
	buf = make([]byte, n)

	if _, err = io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func (s *Stream) readExactlyInt64(n int64) (buf []byte, err error) {
	buf, err = s.readInt64(n)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}

	return
}
