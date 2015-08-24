package pcapng

import (
	"encoding/binary"
	"errors"
)

const (
	PCAPNG_BLOCK_TYPE_SECTION_HEADER = 0x0A0D0D0A
)

type SectionHeaderBlock struct {
	totalLength uint32

	ByteOrder     binary.ByteOrder
	VersionMajor  uint16
	VersionMinor  uint16
	SectionLength int64
	RawOptions    *RawOptions
	Options       *SectionHeaderOptions
}

type SectionHeaderOptions struct {
	Comment         *string
	Hardware        *string
	OS              *string
	UserApplication *string

	Unsupported map[OptionCode][]OptionValue
}

func (SectionHeaderBlock) BlockType() uint32 {
	return BLOCK_TYPE_SECTION_HEADER
}

func (shb SectionHeaderBlock) TotalLength() uint32 {
	return shb.totalLength
}

func (shb SectionHeaderBlock) SupportsSkipping() bool {
	return shb.SectionLength >= 0
}

//
// option helpers
//

func (shb SectionHeaderBlock) HasOptions() bool {
	return shb.Options != nil
}

func (shb SectionHeaderBlock) OptionComment() string {
	if shb.Options == nil || shb.Options.Comment == nil {
		return ""
	}

	return *shb.Options.Comment
}

func (shb SectionHeaderBlock) OptionHardware() string {
	if shb.Options == nil || shb.Options.Hardware == nil {
		return ""
	}

	return *shb.Options.Hardware
}

func (shb SectionHeaderBlock) OptionOS() string {
	if shb.Options == nil || shb.Options.OS == nil {
		return ""
	}

	return *shb.Options.OS
}

func (shb SectionHeaderBlock) OptionUserApplication() string {
	if shb.Options == nil || shb.Options.UserApplication == nil {
		return ""
	}

	return *shb.Options.UserApplication
}

func (s *Stream) readSectionHeaderBlock() (header *SectionHeaderBlock, err error) {
	//
	// Read block type and length
	//
	data, err := s.read(8)
	if err != nil {
		return nil, err
	}

	//
	// check block type
	//
	if !IsPcapngStream(data[:4]) {
		return nil, PCAPNG_INVALID_HEADER
	}

	return s.readSectionHeaderBlockBody(data)
}

func (s *Stream) readSectionHeaderBlockBody(headerData []byte) (header *SectionHeaderBlock, err error) {
	//
	// read byte-order magic, version and section length
	//
	bodyData, err := s.read(16)
	if err != nil {
		return nil, err
	}

	//
	// read byte-order magic
	//
	var byteOrder binary.ByteOrder

	if bodyData[0] == 0x1A && bodyData[1] == 0x2B && bodyData[2] == 0x3C && bodyData[3] == 0x4D {
		byteOrder = binary.BigEndian
	} else if bodyData[3] == 0x1A && bodyData[2] == 0x2B && bodyData[1] == 0x3C && bodyData[0] == 0x4D {
		byteOrder = binary.LittleEndian
	} else {
		return nil, errors.New("invalid byte order mark")
	}

	//
	// read other fields
	//
	versionMajor := byteOrder.Uint16(bodyData[4:6])
	versionMinor := byteOrder.Uint16(bodyData[6:8])
	sectionLength := int64(byteOrder.Uint64(bodyData[8:16]))

	//
	// Read options
	//
	totalLength := byteOrder.Uint32(headerData[4:8])
	optsLen := totalLength - 28
	rawOpts, err := s.readOptions(optsLen, byteOrder)
	if err != nil {
		return nil, err
	}

	opts, err := parseSectionHeaderOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	//
	// Read last block total length
	//
	_, err = s.readExactly(4)
	if err != nil {
		return nil, err
	}

	retval := &SectionHeaderBlock{
		totalLength:   totalLength,
		ByteOrder:     byteOrder,
		VersionMajor:  versionMajor,
		VersionMinor:  versionMinor,
		SectionLength: sectionLength,
		RawOptions:    rawOpts,
		Options:       opts,
	}

	s.sectionHeader = retval
	return retval, nil
}

func parseSectionHeaderOptions(rawOpts *RawOptions) (*SectionHeaderOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &SectionHeaderOptions{}
	opts.Unsupported = make(RawOptions)

	for k, va := range *rawOpts {
		switch k {
		case OPTION_COMMENT:
			val := StringOptionValue(va[0])
			opts.Comment = &val
		case OPTION_SHB_HARDWARE:
			val := StringOptionValue(va[0])
			opts.Hardware = &val
		case OPTION_SHB_OS:
			val := StringOptionValue(va[0])
			opts.OS = &val
		case OPTION_SHB_USERAPPL:
			val := StringOptionValue(va[0])
			opts.UserApplication = &val
		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
