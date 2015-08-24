package pcapng

import (
	"errors"
	"time"
)

type EnhancedPacketBlock struct {
	totalLength    uint32
	Interface      *InterfaceDescriptionBlock
	InterfaceId    uint32
	Timestamp      time.Time
	CapturedLength uint32
	PacketLength   uint32
	PacketData     []byte

	RawOptions *RawOptions
	Options    *EnhancedPacketOptions
}

func (EnhancedPacketBlock) BlockType() uint32 {
	return BLOCK_TYPE_ENHANCED_PACKET
}

func (epb EnhancedPacketBlock) TotalLength() uint32 {
	return epb.totalLength
}

func (epb EnhancedPacketBlock) HasOptions() bool {
	return epb.Options != nil
}

type EnhancedPacketOptions struct {
	Comment   *string
	Flags     *PacketFlags
	Hash      *PacketHash
	DropCount *uint64

	Unsupported RawOptions
}

const (
	PACKET_FLAG_NOT_AVAILABLE = iota
	PACKET_FLAG_INBOUND
	PACKET_FLAG_OUTBOUND
)

type PacketFlagDirection uint8

const (
	DIRECTION_NOT_AVAILABLE PacketFlagDirection = iota
	DIRECTION_INBOUND
	DIRECTION_OUTBOUND
)

type PacketFlags uint32

type PacketFlagReceptionType uint8

const (
	RECEPTION_TYPE_UNSPECIFIED PacketFlagReceptionType = iota
	RECEPTION_TYPE_UNICAST
	RECEPTION_TYPE_MULTICAST
	RECEPTION_TYPE_BROADCAST
)

//
// [00000000 00000000] [0000][000][0 000][000][00]
//
// 2 bits 00-01: direction
// 3 bits 02-04: reception type
// 4 bits 05-08: FCS length
// 7 bits 09-15: reserved
// 8 bits 16-23: unassigned errors
// 8 bits 24-31: errors
//

func (f PacketFlags) Direction() PacketFlagDirection {
	val := f & 0x3 // 0b11

	switch val {
	case 0:
		return DIRECTION_NOT_AVAILABLE
	case 1:
		return DIRECTION_INBOUND
	case 2:
		return DIRECTION_OUTBOUND
	default:
		panic("should not get here")
	}
}

func (f PacketFlags) ReceptionType() (PacketFlagReceptionType, bool) {
	promiscuous := f&0x20 != 0 // 0b100 00
	val := (f & 0xC >> 2)      // 0b011 00

	switch val {
	case 0:
		return RECEPTION_TYPE_UNSPECIFIED, promiscuous
	case 1:
		return RECEPTION_TYPE_UNICAST, promiscuous
	case 2:
		return RECEPTION_TYPE_MULTICAST, promiscuous
	case 3:
		return RECEPTION_TYPE_BROADCAST, promiscuous
	default:
		panic("should not get here")
	}
}

func (f PacketFlags) FCSLength() uint8 {
	return uint8((f & 0x1E0) >> 5) // 0b1111 000 00
}

func (f PacketFlags) ErrorSymbol() bool {
	return f&0x80000000 != 0 // bit 31
}

func (f PacketFlags) ErrorPreamble() bool {
	return f&0x40000000 != 0 // bit 30
}

func (f PacketFlags) ErrorStartFrameDelimiter() bool {
	return f&0x20000000 != 0 // bit 29
}

func (f PacketFlags) ErrorUnalignedFrame() bool {
	return f&0x10000000 != 0 // bit 28
}

func (f PacketFlags) ErrorWrongInterFrameGap() bool {
	return f&0x8000000 != 0 // bit 27
}

func (f PacketFlags) ErrorPacketTooShort() bool {
	return f&0x4000000 != 0 // bit 26
}

func (f PacketFlags) ErrorPacketTooLong() bool {
	return f&0x2000000 != 0 // bit 25
}

func (f PacketFlags) ErrorCRC() bool {
	return f&0x1000000 != 0 // bit 24
}

type PacketHash struct {
	data []byte
}

func (h PacketHash) Algorithm() PacketHashAlgorithm {
	switch h.data[0] {
	case 0:
		return PACKET_HASH_2S_COMPLEMENT
	case 1:
		return PACKET_HASH_XOR
	case 2:
		return PACKET_HASH_CRC32
	case 3:
		return PACKET_HASH_MD5
	case 4:
		return PACKET_HASH_SHA1
	default:
		return PACKET_HASH_UNKNOWN
	}
}

func (h PacketHash) Hash() []byte {
	return h.data[1:]
}

type PacketHashAlgorithm uint8

const (
	PACKET_HASH_2S_COMPLEMENT PacketHashAlgorithm = iota
	PACKET_HASH_XOR
	PACKET_HASH_CRC32
	PACKET_HASH_MD5
	PACKET_HASH_SHA1
	PACKET_HASH_UNKNOWN
)

func (s *Stream) newEnhancedPacketBlock(body []byte, totalLength uint32) (*EnhancedPacketBlock, error) {
	if len(body) < 20 {
		return nil, errors.New("body requires at least 20 bytes of data.")
	}

	byteOrder := s.sectionHeader.ByteOrder

	//
	// parse fields
	//
	interfaceId := byteOrder.Uint32(body[0:4])

	tsHigh := byteOrder.Uint32(body[4:8])
	tsLow := byteOrder.Uint32(body[8:12])

	capLen := byteOrder.Uint32(body[12:16])
	alignedCapLen := alignUint32(capLen)
	packetData := body[20 : 20+alignedCapLen]

	//
	// parse options
	//
	rawOpts, err := s.parseOptions(body[20+alignedCapLen:])
	if err != nil {
		return nil, err
	}

	opts, err := s.parseEnhancedPacketOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	//
	// get interface definition
	//
	if int(interfaceId+1) > len(s.interfaces) {
		return nil, PCAPNG_CORRUPTED_FILE
	}
	ifdb := s.interfaces[interfaceId]

	//
	// done
	//
	return &EnhancedPacketBlock{
		totalLength:    totalLength,
		Interface:    ifdb,
		InterfaceId:    interfaceId,
		Timestamp:      timestamp(tsHigh, tsLow, ifdb),
		CapturedLength: capLen,
		PacketLength:   byteOrder.Uint32(body[16:20]),
		PacketData:     packetData,
		RawOptions:     rawOpts,
		Options:        opts,
	}, nil
}

func (s *Stream) parseEnhancedPacketOptions(rawOpts *RawOptions) (*EnhancedPacketOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &EnhancedPacketOptions{}
	opts.Unsupported = make(RawOptions)

	for k, va := range *rawOpts {
		switch k {
		case OPTION_COMMENT:
			val := StringOptionValue(va[0])
			opts.Comment = &val
		case OPTION_EPB_FLAGS:
			val := PacketFlags(s.sectionHeader.ByteOrder.Uint32(va[0]))
			opts.Flags = &val
		case OPTION_EPB_HASH:
			val := PacketHash{va[0]}
			opts.Hash = &val
		case OPTION_EPB_DROPCOUNT:
			val := s.sectionHeader.ByteOrder.Uint64(va[0])
			opts.DropCount = &val
		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
