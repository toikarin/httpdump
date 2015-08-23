package pcapng

import (
	"errors"
	"fmt"
)

const (
	PCAPNG_BLOCK_BODY_LEN_PROCESS_INFORMATION = 4
)

type ProcessInformationBlock struct {
	totalLength uint32
	ProcessId   uint32

	RawOptions *Options
	Options    *ProcessInformationOptions
}

type ProcessInformationOptions struct {
	Comment     *string
	ProcessName *string
	Unsupported map[OptionCode][]OptionValue
}

func (ProcessInformationBlock) BlockType() uint32 {
	return BLOCK_TYPE_EXPERIMENTAL_PROCESS_INFORMATION
}

func (pib ProcessInformationBlock) TotalLength() uint32 {
	return pib.totalLength
}

func (pib ProcessInformationBlock) HasOptions() bool {
	return pib.Options != nil
}

func (s *Stream) newProcessInformationBlock(body []byte, totalLength uint32) (*ProcessInformationBlock, error) {
	if len(body) < PCAPNG_BLOCK_BODY_LEN_PROCESS_INFORMATION {
		return nil, errors.New(fmt.Sprintf("body requires at least %d bytes of data.", PCAPNG_BLOCK_BODY_LEN_PROCESS_INFORMATION))
	}

	rawOpts, err := ParseOptions2(s.sectionHeader.ByteOrder, body[4:])
	if err != nil {
		return nil, err
	}

	opts, err := s.parseProcessInformationOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	return &ProcessInformationBlock{
		totalLength: totalLength,
		ProcessId:   s.sectionHeader.ByteOrder.Uint32(body[0:4]),
		RawOptions:  rawOpts,
		Options:     opts,
	}, nil
}

func (s *Stream) parseProcessInformationOptions(rawOpts *Options) (*ProcessInformationOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &ProcessInformationOptions{}
	opts.Unsupported = make(map[OptionCode][]OptionValue)

	for k, va := range rawOpts.Values {
		switch k {
		case OPTION_COMMENT:
			v := StringOptionValue(va[0])
			opts.Comment = &v
		case 2:
			v := StringOptionValue(va[0])
			opts.ProcessName = &v
		default:
			opts.Unsupported[k] = va
		}
	}

	return opts, nil
}
