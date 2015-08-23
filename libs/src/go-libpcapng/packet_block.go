package pcapng

import (
	"errors"
	"fmt"
)

const (
	PCAPNG_BLOCK_BODY_LEN_PACKET_BLOCK = 20
)

type PacketBlock struct {
	totalLength uint32

	InterfaceId    uint16
	DropsCount     uint16
	Timestamp      uint64
	CapturedLength uint32
	PacketLength   uint32
	PacketData     []byte

	RawOptions *RawOptions
	Options    *PacketBlockOptions
}

type PacketBlockOptions struct {
	Comment *string
	Flags   *PacketFlags
	Hash    *PacketHash

	Unsupported RawOptions
}

func (PacketBlock) BlockType() uint32 {
	return BLOCK_TYPE_PACKET
}

func (epb PacketBlock) TotalLength() uint32 {
	return epb.totalLength
}

func (epb PacketBlock) HasOptions() bool {
	return epb.Options != nil
}

func (s *Stream) newPacketBlock(body []byte, totalLength uint32) (*PacketBlock, error) {
	if len(body) < PCAPNG_BLOCK_BODY_LEN_PACKET_BLOCK {
		return nil, errors.New(fmt.Sprintf("body requires at least %d bytes of data.", PCAPNG_BLOCK_BODY_LEN_PACKET_BLOCK))
	}

	byteOrder := s.sectionHeader.ByteOrder

	capLen := byteOrder.Uint32(body[12:16])
	alignedCapLen := alignUint32(capLen)
	if int(20+alignedCapLen) > len(body) {
		return nil, errors.New("capLen")
	}

	packetData := body[20 : 20+alignedCapLen]

	//
	// read opts
	//
	rawOpts, err := s.parseOptions(body[20+alignedCapLen:])
	if err != nil {
		return nil, err
	}

	opts, err := s.parsePacketBlockOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	return &PacketBlock{
		totalLength: totalLength,

		InterfaceId:    byteOrder.Uint16(body[0:2]),
		DropsCount:     byteOrder.Uint16(body[2:4]),
		Timestamp:      byteOrder.Uint64(body[4:12]),
		CapturedLength: byteOrder.Uint32(body[12:16]),
		PacketLength:   byteOrder.Uint32(body[16:20]),
		PacketData:     packetData,
		RawOptions:     rawOpts,
		Options:        opts,
	}, nil
}

func (s *Stream) parsePacketBlockOptions(rawOpts *RawOptions) (*PacketBlockOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &PacketBlockOptions{}
	opts.Unsupported = make(map[OptionCode][]OptionValue)

	for k, va := range *rawOpts {
		switch k {
		case OPTION_COMMENT:
			val := StringOptionValue(va[0])
			opts.Comment = &val
		case OPTION_PACK_FLAGS:
			val := PacketFlags(s.sectionHeader.ByteOrder.Uint32(va[0]))
			opts.Flags = &val
		case OPTION_PACK_HASH:
			val := PacketHash{va[0]}
			opts.Hash = &val
		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
