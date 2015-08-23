package pcapng

import (
	"encoding/binary"
	"errors"
	"io"
)

type OptionCode uint16
type OptionValue []byte

type Options struct {
	Values    map[OptionCode][]OptionValue
	byteOrder binary.ByteOrder
}

func (v OptionValue) String() string {
	return string(v)
}

func (v OptionValue) Uint32(byteOrder binary.ByteOrder) (uint32, error) {
	if len(v) != 4 {
		return 0, errors.New("invalid data")
	}

	return byteOrder.Uint32(v), nil
}

func (v OptionValue) Uint64(byteOrder binary.ByteOrder) (uint64, error) {
	if len(v) != 8 {
		return 0, errors.New("invalid data")
	}

	return byteOrder.Uint64(v), nil
}

func ParseOptions2(byteOrder binary.ByteOrder, data []byte) (*Options, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var options *Options
	curData := data

	for {
		//
		// Read code + length
		//
		if len(curData) < 4 {
			return nil, io.ErrUnexpectedEOF
		}

		optionCode := OptionCode(byteOrder.Uint16(curData[:2]))
		optionLen := byteOrder.Uint16(curData[2:4])

		if optionCode == OPTION_CODE_END_OF_OPT {
			break
		}

		curData = curData[4:]

		//
		// read value
		//
		if len(curData) < int(optionLen) {
			return nil, io.ErrUnexpectedEOF
		}
		optionValue := curData[:optionLen]

		//
		// check if this is new option
		//
		if options == nil {
			options = &Options{
				Values:    make(map[OptionCode][]OptionValue, 0),
				byteOrder: byteOrder,
			}
		}
		optionValueArray, ok := options.Values[optionCode]
		if !ok {
			optionValueArray = make([]OptionValue, 0)
			options.Values[optionCode] = optionValueArray
		}

		options.Values[optionCode] = append(optionValueArray, optionValue)

		boundary := alignUint16(optionLen)
		curData = curData[boundary:]
	}

	return options, nil
}
