package pcapng

import (
	"encoding/binary"
	"errors"
	"io"
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
	RawOptions    *Options
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

func ReadSectionHeaderBlock(r io.Reader) (header *SectionHeaderBlock, err error) {
	data, err := read(r, 8)
	if err != nil {
		return nil, err
	}

	//
	// read block-type
	//
	if data[0] != 0x0A || data[1] != 0x0D || data[2] != 0x0D || data[3] != 0x0A {
		return nil, PCAPNG_INVALID_HEADER
	}

	return readSectionHeaderBlock(r, data)
}

func readSectionHeaderBlock(r io.Reader, headerData []byte) (header *SectionHeaderBlock, err error) {
	bodyData, err := read(r, 24-8)
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
	// Read options
	//
	totalLength := byteOrder.Uint32(headerData[4:8])
	optsLen := totalLength - 28
	rawOpts, err := readOptions(r, byteOrder, optsLen)
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
	_, err = readExactly(r, 4)
	if err != nil {
		return nil, err
	}

	return &SectionHeaderBlock{
		totalLength:   totalLength,
		ByteOrder:     byteOrder,
		VersionMajor:  byteOrder.Uint16(bodyData[4:6]),
		VersionMinor:  byteOrder.Uint16(bodyData[6:8]),
		SectionLength: int64(byteOrder.Uint64(bodyData[8:16])),
		RawOptions:    rawOpts,
		Options:       opts,
	}, nil
}

func parseSectionHeaderOptions(rawOpts *Options) (*SectionHeaderOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &SectionHeaderOptions{}
	opts.Unsupported = make(map[OptionCode][]OptionValue)

	for k, va := range rawOpts.Values {
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
