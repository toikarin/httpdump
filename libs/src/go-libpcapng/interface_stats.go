package pcapng

import (
	"time"
)

type InterfaceStatisticsBlock struct {
	totalLength uint32
	InterfaceId uint32
	Interface   *InterfaceDescriptionBlock
	Timestamp   time.Time

	RawOptions *RawOptions
	Options    *InterfaceStatisticsOptions
}

func (InterfaceStatisticsBlock) BlockType() uint32 {
	return BLOCK_TYPE_INTERFACE_STATS
}

func (ifsb InterfaceStatisticsBlock) TotalLength() uint32 {
	return ifsb.totalLength
}

func (ifsb InterfaceStatisticsBlock) HasOptions() bool {
	return ifsb.Options != nil
}

type InterfaceStatisticsOptions struct {
	Comment      *string
	StartTime    *time.Time
	EndTime      *time.Time
	IfRecv       *uint16
	IfDrop       *uint16
	FilterAccept *uint16
	OsDrop       *uint16
	UsrDeliv     *uint16

	Unsupported RawOptions
}

func (s *Stream) newInterfaceStatisticsBlock(body []byte, totalLength uint32) (*InterfaceStatisticsBlock, error) {
	//
	// parse fields
	//
	byteOrder := s.sectionHeader.ByteOrder
	interfaceId := byteOrder.Uint32(body[0:4])
	tsHigh := byteOrder.Uint32(body[4:8])
	tsLow := byteOrder.Uint32(body[8:12])

	//
	// get interface definition
	//
	if int(interfaceId+1) > len(s.interfaces) {
		return nil, PCAPNG_CORRUPTED_FILE
	}
	ifdb := s.interfaces[interfaceId]

	//
	// parse options
	//
	rawOpts, err := s.parseOptions(body[12:])
	if err != nil {
		return nil, err
	}

	opts, err := s.parseInterfaceStatisticsOptions(rawOpts, ifdb)
	if err != nil {
		return nil, err
	}

	return &InterfaceStatisticsBlock{
		totalLength: totalLength,
		InterfaceId: interfaceId,
		Interface:   ifdb,
		Timestamp:   timestamp(tsHigh, tsLow, ifdb),
		RawOptions:  rawOpts,
		Options:     opts,
	}, nil
}

func (s *Stream) parseInterfaceStatisticsOptions(rawOpts *RawOptions, ifdb *InterfaceDescriptionBlock) (*InterfaceStatisticsOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &InterfaceStatisticsOptions{}
	opts.Unsupported = make(RawOptions)

	for k, va := range *rawOpts {
		switch k {
		case OPTION_COMMENT:
			val := StringOptionValue(va[0])
			opts.Comment = &val
		case OPTION_ISB_STARTTIME:
			high := s.sectionHeader.ByteOrder.Uint32(va[0][0:4])
			low := s.sectionHeader.ByteOrder.Uint32(va[0][4:8])

			val := timestamp(high, low, ifdb)
			opts.StartTime = &val
		case OPTION_ISB_ENDTIME:
			high := s.sectionHeader.ByteOrder.Uint32(va[0][0:4])
			low := s.sectionHeader.ByteOrder.Uint32(va[0][4:8])

			val := timestamp(high, low, ifdb)
			opts.EndTime = &val
		case OPTION_ISB_IFRECV:
			val := s.sectionHeader.ByteOrder.Uint16(va[0])
			opts.IfRecv = &val
		case OPTION_ISB_IFDROP:
			val := s.sectionHeader.ByteOrder.Uint16(va[0])
			opts.IfDrop = &val
		case OPTION_ISB_FILTERACCEPT:
			val := s.sectionHeader.ByteOrder.Uint16(va[0])
			opts.FilterAccept = &val
		case OPTION_ISB_OSDROP:
			val := s.sectionHeader.ByteOrder.Uint16(va[0])
			opts.OsDrop = &val
		case OPTION_ISB_USRDELIV:
			val := s.sectionHeader.ByteOrder.Uint16(va[0])
			opts.UsrDeliv = &val
		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
