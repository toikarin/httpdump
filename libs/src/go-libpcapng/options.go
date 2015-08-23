package pcapng

import (
	"encoding/binary"
	"io"
)

const (
	OPTION_CODE_END_OF_OPT = 0
	OPTION_COMMENT         = 1

	OPTION_SHB_HARDWARE = 2
	OPTION_SHB_OS       = 3
	OPTION_SHB_USERAPPL = 4

	OPTION_IF_NAME        = 2
	OPTION_IF_DESCRIPTION = 3
	OPTION_IF_IPV4ADDR    = 4
	OPTION_IF_IPV6ADDR    = 5
	OPTION_IF_MACADDR     = 6
	OPTION_IF_EUIADDR     = 7
	OPTION_IF_SPEED       = 8
	OPTION_IF_TSRESOL     = 9
	OPTION_IF_TZONE       = 10
	OPTION_IF_FILTER      = 11
	OPTION_IF_OS          = 12
	OPTION_IF_FCSLEN      = 13
	OPTION_IF_TSOFFSET    = 14

	OPTION_LEN_IF_IPV4ADDR = 8
	OPTION_LEN_IF_IPV6ADDR = 17
	OPTION_LEN_IF_MACADDR  = 6
	OPTION_LEN_IF_EUIADDR  = 8
	OPTION_LEN_IF_SPEED    = 8
	OPTION_LEN_IF_TSRESOL  = 1
	OPTION_LEN_IF_TSZONE   = 4
	OPTION_LEN_IF_FCSLEN   = 1
	OPTION_LEN_IF_TSOFFSET = 8

	OPTION_EPB_FLAGS     = 2
	OPTION_EPB_HASH      = 3
	OPTION_EPB_DROPCOUNT = 4

	OPTION_LEN_EPB_FLAGS     = 4
	OPTION_LEN_EPB_DROPCOUNT = 8

	OPTION_PACK_FLAGS = 2
	OPTION_PACK_HASH  = 3

	OPTION_LEN_PACK_FLAGS = 4

	OPTION_NS_DNSNAME = 2
	OPTION_DNSIP4ADDR = 3
	OPTION_DNSIP6ADDR = 4

	OPTION_LEN_DNSIP4ADDR = 4
	OPTION_LEN_DNSIP6ADDR = 16

	OPTION_ISB_STARTTIME    = 2
	OPTION_ISB_ENDTIME      = 3
	OPTION_ISB_IFRECV       = 4
	OPTION_ISB_IFDROP       = 5
	OPTION_ISB_FILTERACCEPT = 6
	OPTION_ISB_OSDROP       = 7
	OPTION_ISB_USRDELIV     = 8

	OPTION_LEN_ISB_STARTTIME    = 8
	OPTION_LEN_ISB_ENDTIME      = 8
	OPTION_LEN_ISB_IFRECV       = 8
	OPTION_LEN_ISB_IFDROP       = 8
	OPTION_LEN_ISB_FILTERACCEPT = 8
	OPTION_LEN_ISB_OSDROP       = 8
	OPTION_LEN_ISB_USRDELIV     = 8

	// experimental
	OPTION_EXP_PIB_NAME = 2
	OPTION_EXP_PIB_PATH = 3

	OPTION_EXP_EPB_PIB_INDEX           = 0x8001
	OPTION_EXP_EPB_SERVICE_CODE        = 0x8002
	OPTION_EXP_EPB_EFFECTIVE_PIB_INDEX = 0x8003
)

type Option struct {
	Code  uint16
	Value []byte
}

func ParseOptions(bo binary.ByteOrder, data []byte) ([]Option, error) {
	if len(data) == 0 {
		return nil, nil
	}

	curData := data
	retval := make([]Option, 0)

	for {
		//
		// Read code + length
		//
		if len(curData) < 4 {
			return nil, io.ErrUnexpectedEOF
		}

		optionCode := bo.Uint16(curData[:2])
		optionLen := bo.Uint16(curData[2:4])

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

		retval = append(retval, Option{optionCode, optionValue})

		boundary := alignUint16(optionLen)
		curData = curData[boundary:]
	}

	return retval, nil
}
