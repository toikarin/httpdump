package pcapng

import (
	"encoding/binary"
	"io"
)

const (
	PCAPNG_RECORD_CODE_END_OF_RECORD = 0
)

type Record struct {
	Type  uint16
	Value []byte
}

type IPv4Address [4]uint8
type IPv6Address [8]uint16

func NewIPv6Address(byteOrder binary.ByteOrder, data []byte) IPv6Address {
	return IPv6Address{
		byteOrder.Uint16(data[0:2]),
		byteOrder.Uint16(data[2:4]),
		byteOrder.Uint16(data[4:6]),
		byteOrder.Uint16(data[6:8]),
		byteOrder.Uint16(data[8:10]),
		byteOrder.Uint16(data[10:12]),
		byteOrder.Uint16(data[12:14]),
		byteOrder.Uint16(data[14:16]),
	}
}

type IPv4Record struct {
	Address IPv4Address
	Name    string
}

type IPv6Record struct {
	Address IPv6Address
	Name    string
}

type NameResolutionBlock struct {
	totalLength uint32

	IPv4Records []IPv4Record
	IPv6Records []IPv6Record
	RawOptions  *RawOptions
	Options     *NameResolutionOptions
}

type NameResolutionOptions struct {
	Comment *string

	DnsName     *string
	IPv4Address *IPv4Address
	IPv6Address *IPv6Address

	Unsupported RawOptions
}

func (NameResolutionBlock) BlockType() uint32 {
	return BLOCK_TYPE_NAME_RESOLUTION
}

func (nrb NameResolutionBlock) TotalLength() uint32 {
	return nrb.totalLength
}

func (nrb NameResolutionBlock) HasOptions() bool {
	return nrb.Options != nil
}

func (nrb NameResolutionBlock) OptionComment() string {
	if nrb.Options == nil || nrb.Options.Comment == nil {
		return ""
	}

	return *nrb.Options.Comment
}

func (s *Stream) newNameResolutionBlock(body []byte, totalLength uint32) (*NameResolutionBlock, error) {
	byteOrder := s.sectionHeader.ByteOrder

	curData := body
	ipv4records := make([]IPv4Record, 0)
	ipv6records := make([]IPv6Record, 0)

	//
	// Parse records
	//
	for {
		//
		// read type + length
		//
		if len(curData) < 4 {
			return nil, io.ErrUnexpectedEOF
		}

		recordType := byteOrder.Uint16(curData[:2])
		recordLength := byteOrder.Uint16(curData[2:4])

		if recordType == PCAPNG_RECORD_CODE_END_OF_RECORD {
			break
		}

		curData = curData[4:]

		//
		// read value
		//
		if len(curData) < int(recordLength) {
			return nil, io.ErrUnexpectedEOF
		}
		recordValue := curData[:recordLength]

		switch recordType {
		case 1:
			if recordLength < 4 {
				return nil, io.ErrUnexpectedEOF
			}

			var addr [4]byte
			copy(addr[:], recordValue[:4])

			ipv4records = append(ipv4records, IPv4Record{addr, string(recordValue[4 : recordLength-1])})
		case 2:
			if recordLength < 16 {
				return nil, io.ErrUnexpectedEOF
			}

			addr := NewIPv6Address(byteOrder, recordValue[:16])

			ipv6records = append(ipv6records, IPv6Record{addr, string(recordValue[16 : recordLength-1])})
		default:
			// FIXME
		}

		boundary := alignUint16(recordLength)
		curData = curData[boundary:]
	}

	//
	// Read options
	//
	rawOpts, err := s.parseOptions(curData)
	if err != nil {
		return nil, err
	}

	opts, err := s.parseNameResolutionOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	return &NameResolutionBlock{
		totalLength: totalLength,
		IPv4Records: ipv4records,
		IPv6Records: ipv6records,
		RawOptions:  rawOpts,
		Options:     opts,
	}, nil
}

func (s *Stream) parseNameResolutionOptions(rawOpts *RawOptions) (*NameResolutionOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &NameResolutionOptions{}
	opts.Unsupported = make(RawOptions)

	for k, va := range *rawOpts {
		switch k {
		case OPTION_COMMENT:
			val := StringOptionValue(va[0])
			opts.Comment = &val
		case OPTION_NS_DNSNAME:
			val := StringOptionValue(va[0])
			opts.DnsName = &val
		case OPTION_DNSIP4ADDR:
			val := va[0]
			var addr [4]byte
			copy(addr[:], val)
			ipv4addr := IPv4Address(addr)

			opts.IPv4Address = &ipv4addr
		case OPTION_DNSIP6ADDR:
			val := va[0]
			addr := NewIPv6Address(s.sectionHeader.ByteOrder, val)
			opts.IPv6Address = &addr

		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
