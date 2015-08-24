package pcapng

type ProcessInformationBlock struct {
	totalLength uint32
	ProcessId   uint32

	RawOptions *RawOptions
	Options    *ProcessInformationOptions
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

type ProcessInformationOptions struct {
	Comment     *string
	ProcessName *string
	Unsupported RawOptions
}

//
// parsing
//

func (s *Stream) newProcessInformationBlock(body []byte, totalLength uint32) (*ProcessInformationBlock, error) {
	//
	// parse fields
	//
	pid := s.sectionHeader.ByteOrder.Uint32(body[0:4])

	//
	// parse options
	//
	rawOpts, err := s.parseOptions(body[4:])
	if err != nil {
		return nil, err
	}

	opts, err := s.parseProcessInformationOptions(rawOpts)
	if err != nil {
		return nil, err
	}

	return &ProcessInformationBlock{
		totalLength: totalLength,
		ProcessId:   pid,
		RawOptions:  rawOpts,
		Options:     opts,
	}, nil
}

func (s *Stream) parseProcessInformationOptions(rawOpts *RawOptions) (*ProcessInformationOptions, error) {
	if rawOpts == nil {
		return nil, nil
	}

	opts := &ProcessInformationOptions{}
	opts.Unsupported = make(RawOptions)

	for k, va := range *rawOpts {
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
