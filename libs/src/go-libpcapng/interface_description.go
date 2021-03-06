package pcapng

const (
	DEFAULT_TIMESTAMP_RESOLUTION = TimestampResolution(6)
)

//
// InterfaceDescriptionBlock
//

type InterfaceDescriptionBlock struct {
	totalLength uint32

	LinkType   uint16
	SnapLength uint32

	RawOptions *RawOptions
	Options    *InterfaceDescriptionOptions
}

func (InterfaceDescriptionBlock) BlockType() uint32 {
	return BLOCK_TYPE_INTERFACE_DESC
}

func (ifdp InterfaceDescriptionBlock) TotalLength() uint32 {
	return ifdp.totalLength
}

func (ifdb InterfaceDescriptionBlock) OptionName() string {
	if ifdb.Options != nil && ifdb.Options.Name != nil {
		return *ifdb.Options.Name
	}

	return ""
}

func (ifdb InterfaceDescriptionBlock) OptionDescription() string {
	if ifdb.Options != nil && ifdb.Options.Description != nil {
		return *ifdb.Options.Description
	}

	return ""
}

func (ifdb InterfaceDescriptionBlock) OptionTimestampResolution() TimestampResolution {
	if ifdb.Options != nil && ifdb.Options.TimestampResolution != nil {
		return *ifdb.Options.TimestampResolution
	}

	return DEFAULT_TIMESTAMP_RESOLUTION
}

//
// InterfaceDescriptionOptions
//

type InterfaceDescriptionOptions struct {
	Comment *string

	Name                *string
	Description         *string
	IPv4Address         *IPv4Address
	IPv6Address         *IPv6Address
	MacAddress          []byte
	EUIAddress          []byte
	Speed               *uint64
	TimestampResolution *TimestampResolution
	Timezone            []byte
	Filter              *CaptureFilter
	OS                  *string
	FCSLength           *uint8
	TimestampOffset     *uint64

	Unsupported RawOptions
}

type CaptureFilter struct {
	Code    uint8
	Details string
}

type TimestampResolution uint8

func (tsr TimestampResolution) IsPow10() bool {
	return tsr&0x80 == 0
}
func (tsr TimestampResolution) Value() uint8 {
	return uint8(tsr & 0x7F)
}

//
// parsing
//

func (s *Stream) newInterfaceDescriptionBlock(body []byte, totalLength uint32) (*InterfaceDescriptionBlock, error) {
	byteOrder := s.sectionHeader.ByteOrder

	//
	// parse fields
	//
	linkType := byteOrder.Uint16(body[0:2])
	snapLength := byteOrder.Uint32(body[4:8])

	//
	// parse options
	//
	rawOpts, err := s.parseOptions(body[8:])
	if err != nil {
		return nil, err
	}

	opts, err := s.parseInterfaceDescriptionOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	return &InterfaceDescriptionBlock{
		totalLength: totalLength,
		LinkType:    linkType,
		SnapLength:  snapLength,
		RawOptions:  rawOpts,
		Options:     opts,
	}, nil
}

func (s *Stream) parseInterfaceDescriptionOptions(rawOpts *RawOptions) (*InterfaceDescriptionOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &InterfaceDescriptionOptions{}
	opts.Unsupported = make(RawOptions)

	for k, va := range *rawOpts {
		switch k {
		case OPTION_COMMENT:
			v := StringOptionValue(va[0])
			opts.Comment = &v
		case OPTION_IF_NAME:
			v := StringOptionValue(va[0])
			opts.Name = &v
		case OPTION_IF_DESCRIPTION:
			v := StringOptionValue(va[0])
			opts.Description = &v
		case OPTION_IF_IPV4ADDR:
			v := newIPv4Address(va[0])
			opts.IPv4Address = &v
		case OPTION_IF_IPV6ADDR:
			addr := newIPv6Address(s.sectionHeader.ByteOrder, va[0])
			opts.IPv6Address = &addr
		case OPTION_IF_MACADDR:
			v := va[0]
			opts.MacAddress = v
		case OPTION_IF_EUIADDR:
			v := va[0]
			opts.EUIAddress = v
		case OPTION_IF_SPEED:
			v := s.sectionHeader.ByteOrder.Uint64(va[0])
			opts.Speed = &v
		case OPTION_IF_TSRESOL:
			v := TimestampResolution(va[0][0])
			opts.TimestampResolution = &v
		case OPTION_IF_TZONE:
			v := va[0]
			opts.Timezone = v
		case OPTION_IF_FILTER:
			v := va[0]
			cf := CaptureFilter{v[0], StringOptionValue(v[1:])}
			opts.Filter = &cf
		case OPTION_IF_OS:
			v := StringOptionValue(va[0])
			opts.OS = &v
		case OPTION_IF_FCSLEN:
			v := va[0][0]
			opts.FCSLength = &v
		case OPTION_IF_TSOFFSET:
			v := s.sectionHeader.ByteOrder.Uint64(va[0])
			opts.TimestampOffset = &v
		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
