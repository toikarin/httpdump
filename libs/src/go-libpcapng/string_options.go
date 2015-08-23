package pcapng

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

func String(opts []Option, blockType uint32, bo binary.ByteOrder) string {
	s := ""

	for i, opt := range opts {
		if i > 0 {
			s += ",\n"
		}
		s += opt.String(blockType, bo)
	}

	return s
}

func (o Option) String(blockType uint32, bo binary.ByteOrder) string {
	return fmt.Sprintf(`[Option:
    Name:         %s
    Value:        %s
]`, o.CodeString(blockType), o.ValueString(blockType, bo))
}

func (o Option) CodeString(blockType uint32) string {
	//
	// generic
	//
	switch o.Code {
	case OPTION_COMMENT:
		return "comment"
	}

	//
	// block specific
	//
	switch blockType {
	case BLOCK_TYPE_EXPERIMENTAL_PROCESS_INFORMATION:
		switch o.Code {
		case OPTION_EXP_PIB_NAME:
			return "name"
		case OPTION_EXP_PIB_PATH:
			return "path"
		}
	case BLOCK_TYPE_SECTION_HEADER:
		switch o.Code {
		case OPTION_SHB_HARDWARE:
			return "hardware"
		case OPTION_SHB_OS:
			return "os"
		case OPTION_SHB_USERAPPL:
			return "userappl"
		}
	case BLOCK_TYPE_INTERFACE_DESC:
		switch o.Code {
		case OPTION_IF_NAME:
			return "if_name"
		case OPTION_IF_DESCRIPTION:
			return "if_description"
		case OPTION_IF_IPV4ADDR:
			return "if_IPv4addr"
		case OPTION_IF_IPV6ADDR:
			return "if_IP64addr"
		case OPTION_IF_MACADDR:
			return "if_MACaddr"
		case OPTION_IF_EUIADDR:
			return "if_EUIaddr"
		case OPTION_IF_SPEED:
			return "if_speed"
		case OPTION_IF_TSRESOL:
			return "if_tsresol"
		case OPTION_IF_TZONE:
			return "if_tzone"
		case OPTION_IF_FILTER:
			return "if_filter"
		case OPTION_IF_OS:
			return "if_os"
		case OPTION_IF_FCSLEN:
			return "if_fcslen"
		case OPTION_IF_TSOFFSET:
			return "if_tsoffset"
		}
	case BLOCK_TYPE_PACKET:
		switch o.Code {
		case OPTION_PACK_FLAGS:
			return "flags"
		case OPTION_PACK_HASH:
			return "hash"
		}
	case BLOCK_TYPE_NAME_RESOLUTION:
		switch o.Code {
		case OPTION_NS_DNSNAME:
			return "dnsname"
		case OPTION_DNSIP4ADDR:
			return "dnsIP4addr"
		case OPTION_DNSIP6ADDR:
			return "dnsIP6addr"
		}
	case BLOCK_TYPE_INTERFACE_STATS:
		switch o.Code {
		case OPTION_ISB_STARTTIME:
			return "starttime"
		case OPTION_ISB_ENDTIME:
			return "endtime"
		case OPTION_ISB_IFRECV:
			return "ifrecv"
		case OPTION_ISB_IFDROP:
			return "ifdrop"
		case OPTION_ISB_FILTERACCEPT:
			return "filteraccept"
		case OPTION_ISB_OSDROP:
			return "osdrop"
		case OPTION_ISB_USRDELIV:
			return "usrdeliv"
		}
	case BLOCK_TYPE_ENHANCED_PACKET:
		switch o.Code {
		case OPTION_EPB_FLAGS:
			return "flags"
		case OPTION_EPB_HASH:
			return "hash"
		case OPTION_EPB_DROPCOUNT:
			return "dropcount"
		case OPTION_EXP_EPB_PIB_INDEX:
			return "process information id (experimental)"
		case OPTION_EXP_EPB_SERVICE_CODE:
			return "service code (experimental)"
		case OPTION_EXP_EPB_EFFECTIVE_PIB_INDEX:
			return "effective process information id (experimental)"
		}
	}

	return fmt.Sprintf("unknown [type: %d, code: %d]", blockType, o.Code)
}

func (o Option) ValueString(blockType uint32, bo binary.ByteOrder) string {
	//
	// generic
	//
	switch o.Code {
	case OPTION_COMMENT:
		return string(o.Value)
	}

	// specific to block type
	switch blockType {
	case BLOCK_TYPE_EXPERIMENTAL_PROCESS_INFORMATION:
		switch o.Code {
		case OPTION_EXP_PIB_NAME:
			fallthrough
		case OPTION_EXP_PIB_PATH:
			return string(o.Value)
		}
	case BLOCK_TYPE_SECTION_HEADER:
		switch o.Code {
		case OPTION_SHB_HARDWARE:
			fallthrough
		case OPTION_SHB_OS:
			fallthrough
		case OPTION_SHB_USERAPPL:
			return string(o.Value)
		}
	case BLOCK_TYPE_INTERFACE_DESC:
		switch o.Code {
		//
		// string values
		//
		case OPTION_IF_NAME:
			fallthrough
		case OPTION_IF_DESCRIPTION:
			fallthrough
		case OPTION_IF_OS:
			return string(o.Value)
		//
		// uint8 values
		//
		case OPTION_IF_FCSLEN:
			return strconv.FormatInt(int64(o.Value[0]), 10)
		//
		// int64 values
		//
		case OPTION_IF_SPEED:
			fallthrough
		case OPTION_IF_TSOFFSET:
			return strconv.FormatUint(bo.Uint64(o.Value), 10)

		//
		// values with printed byte array
		//
		case OPTION_IF_IPV4ADDR:
			fallthrough
		case OPTION_IF_IPV6ADDR:
			fallthrough
		case OPTION_IF_MACADDR:
			fallthrough
		case OPTION_IF_EUIADDR:
			fallthrough
		case OPTION_IF_TSRESOL:
			fallthrough
		case OPTION_IF_TZONE:
			fallthrough
		case OPTION_IF_FILTER:
			fallthrough
		default:
			return fmt.Sprintf("%s", o.Value)
		}
	case BLOCK_TYPE_PACKET:
		fallthrough
	case BLOCK_TYPE_SIMPLE_PACKET:
		fallthrough
	case BLOCK_TYPE_NAME_RESOLUTION:
		fallthrough
	case BLOCK_TYPE_INTERFACE_STATS:
		fallthrough
	case BLOCK_TYPE_ENHANCED_PACKET:
		switch o.Code {
		//
		// uint32
		//
		case OPTION_EXP_EPB_PIB_INDEX:
			fallthrough
		case OPTION_EXP_EPB_SERVICE_CODE:
			fallthrough
		case OPTION_EXP_EPB_EFFECTIVE_PIB_INDEX:
			fallthrough
		case OPTION_EPB_DROPCOUNT:
			return strconv.FormatUint(uint64(bo.Uint32(o.Value)), 10)
		//
		//
		//
		case OPTION_EPB_FLAGS:
			return ebpFlagToString(bo.Uint32(o.Value))
		case OPTION_EPB_HASH:
			fallthrough
		default:
			return fmt.Sprintf("%s", o.Value)
		}
	}

	return fmt.Sprintf("unknown [type: %d, code: %d, value: %s]", blockType, o.Code, o.Value)
}

func ebpFlagDirectionString(f uint32) string {
	switch f & 0x3 {
	case 0:
		return "unspecified"
	case 1:
		return "inbound"
	case 2:
		return "outbound"
	default:
		panic("should not get here")
	}
}

func ebpFlagReceptionTypeString(f uint32) string {
	switch f & 0x3C {
	case 0:
		return "unspecified"
	case 1:
		return "unicast"
	case 2:
		return "multicast"
	case 3:
		return "broadcast"
	case 4:
		return "promiscuous"
	default:
		return strconv.FormatUint(uint64(f&0x3C), 16)
	}
}

func ebpFlagErrors(f uint32) string {
	errors := make([]string, 0)

	if f&0x80000000 != 0 {
		errors = append(errors, "symbol")
	}

	if f&0x40000000 != 0 {
		errors = append(errors, "preamble")
	}

	if f&0x20000000 != 0 {
		errors = append(errors, "start frame delimiter")
	}

	if f&0x10000000 != 0 {
		errors = append(errors, "unaligned frame")
	}

	if f&0x8000000 != 0 {
		errors = append(errors, "wrong inter frame gap")
	}

	if f&0x4000000 != 0 {
		errors = append(errors, "packet too short")
	}

	if f&0x2000000 != 0 {
		errors = append(errors, "packet too long")
	}

	if f&0x1000000 != 0 {
		errors = append(errors, "crc error")
	}

	if len(errors) > 0 {
		return strings.Join(errors, ",")
	} else {
		return "none"
	}
}

func ebpFlagToString(f uint32) string {
	return fmt.Sprintf("[Inbound/Output: %s, Reception Type: %s, FCS length: %d, Link Layer errors: [%s]] (raw: 0b%032s)",
		ebpFlagDirectionString(f), ebpFlagReceptionTypeString(f), f&0x1E0, ebpFlagErrors(f), strconv.FormatUint(uint64(f), 2))
}
