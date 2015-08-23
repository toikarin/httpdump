package pcapng

import (
	"errors"
	"fmt"
	"time"
)

const (
	PCAPNG_BLOCK_BODY_LEN_INTERFACE_STATS = 12
)

type InterfaceStatisticsBlock struct {
	totalLength uint32
	InterfaceId uint32
	Interface   *InterfaceDescriptionBlock
	Timestamp   time.Time

	RawOptions *Options
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

	Unsupported map[OptionCode][]OptionValue
}

func uint16opt(s *Stream, o *Options, oc OptionCode) (*uint16, error) {
	var retval *uint16

	valarray, ok := o.Values[oc]
	if ok {
		val := valarray[0]

		if len(val) != 8 {
			return nil, errors.New("corrupted value")
		}

		ref := s.sectionHeader.ByteOrder.Uint16(val)
		retval = &ref
	}

	return retval, nil
}

func (s *Stream) timestampValue(o *Options, oc OptionCode, ifdb *InterfaceDescriptionBlock) (*time.Time, error) {
	val, ok := o.Values[oc]
	if ok {
		if len(val[0]) != 8 {
			return nil, errors.New("corrupted value")
		}

		high := s.sectionHeader.ByteOrder.Uint32(val[0][0:4])
		low := s.sectionHeader.ByteOrder.Uint32(val[0][4:8])

		val := timestamp(high, low, ifdb)
		return &val, nil
	}

	return nil, nil
}

func (s *Stream) newInterfaceStatisticsBlock(body []byte, totalLength uint32) (*InterfaceStatisticsBlock, error) {
	if len(body) < PCAPNG_BLOCK_BODY_LEN_INTERFACE_STATS {
		return nil, errors.New(fmt.Sprintf("body requires at least %d bytes of data.", PCAPNG_BLOCK_BODY_LEN_INTERFACE_STATS))
	}

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
	rawOpts, err := ParseOptions2(byteOrder, body[12:])
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

func (s *Stream) parseInterfaceStatisticsOptions(rawOpts *Options, ifdb *InterfaceDescriptionBlock) (*InterfaceStatisticsOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &InterfaceStatisticsOptions{}
	opts.Unsupported = make(map[OptionCode][]OptionValue)

	for k, va := range rawOpts.Values {
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
