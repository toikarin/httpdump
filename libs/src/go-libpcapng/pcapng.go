package pcapng

import (
	"errors"
	"math"
	"time"
)

//
// +----------------------------------------------------------+
// | General Block Structure                                  |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Block Type         | 4 bytes                             |
// | Block Total Length | 4 bytes                             |
// | Block Body         | variable length, aligned to 4 bytes |
// | Block Total Length | 4 bytes                             |
// +--------------------+-------------------------------------+
//
// Block bodies:
// -------------
//
// +----------------------------------------------------------+
// | Section Header Block (0x0A0D0D0A)                        |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Byte Order Magic   | 4 bytes                             |
// | Major Version      | 2 bytes                             |
// | Minor Version      | 2 bytes                             |
// | Section Length     | 4 bytes                             |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// +----------------------------------------------------------+
// | Interface Description Block (0x00000001)                 |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Link Type          | 2 bytes                             |
// | <RESERVED>         | 2 bytes                             |
// | SnapLen            | 4 bytes                             |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// +----------------------------------------------------------+
// | Packet Block (0x00000002) (OBSOLETE)                     |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Interface Id       | 2 bytes                             |
// | Drops Count        | 2 bytes                             |
// | Timestamp (High)   | 4 bytes                             |
// | Timestamp (Low)    | 4 bytes                             |
// | Captured Len       | 4 bytes                             |
// | Packet Len         | 4 bytes                             |
// | Packet Data        | variable length, aligned to 4 bytes |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// +----------------------------------------------------------+
// | Simple Packet Block (0x00000003)                         |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Packet Len         | 4 bytes                             |
// | Packet Data        | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// +----------------------------------------------------------+
// | Name Resolution Block (0x00000004)                       |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Record Type        | 2 bytes                             |
// | Record Length      | 2 bytes                             |
// | Packet Value       | variable length, aligned to 4 bytes |
// | ...                                                      |
// | Record End         | 4 bytes                             |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// +----------------------------------------------------------+
// | Interface Statistics Block (0x00000005)                  |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Interface Id       | 4 bytes                             |
// | Timestamp (High)   | 4 bytes                             |
// | Timestamp (Low)    | 4 bytes                             |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// +----------------------------------------------------------+
// | Enhanced Packet Block (0x00000006)                       |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Interface Id       | 4 bytes                             |
// | Timestamp (High)   | 4 bytes                             |
// | Timestamp (Low)    | 4 bytes                             |
// | Captured Len       | 4 bytes                             |
// | Packet Len         | 4 bytes                             |
// | Packet Data        | variable length, aligned to 4 bytes |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// Experimentals / extensions:
//
// +----------------------------------------------------------+
// | Process Information Block (0x80000001) (Apple extension) |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Process Id         | 4 bytes                             |
// | Options            | variable length, aligned to 4 bytes |
// +--------------------+-------------------------------------+
//
// Options:
//
// +----------------------------------------------------------+
// | Options                                                  |
// +--------------------+-------------------------------------+
// | Name               | Length                              |
// +--------------------+-------------------------------------+
// | Option Code        | 2 bytes                             |
// | Option Length      | 2 bytes                             |
// | Option Value       | variable length, aligned to 4 bytes |
// | ...                                                      |
// | Option End         | 4 bytes                             |
// +--------------------+-------------------------------------+
//

const (
	SECTION_HEADER_MIN_LENGTH     = 28
	BLOCK_TOTAL_LENGTH_BYTES      = 4
	BLOCK_LEN_INTERFACE_DESC      = 14
	BLOCK_BODY_LEN_SECTION_HEADER = 16
)

const (
	BLOCK_TYPE_SECTION_HEADER  = 0x0A0D0D0A
	BLOCK_TYPE_INTERFACE_DESC  = 0x00000001
	BLOCK_TYPE_PACKET          = 0x00000002 // obsolete
	BLOCK_TYPE_SIMPLE_PACKET   = 0x00000003
	BLOCK_TYPE_NAME_RESOLUTION = 0x00000004
	BLOCK_TYPE_INTERFACE_STATS = 0x00000005
	BLOCK_TYPE_ENHANCED_PACKET = 0x00000006

	// experimental
	BLOCK_TYPE_EXPERIMENTAL_PROCESS_INFORMATION = 0x80000001
)

type Block interface {
	BlockType() uint32
	TotalLength() uint32
}

type blockHeader struct {
	BlockType   uint32
	TotalLength uint32
}

var PCAPNG_INVALID_HEADER = errors.New("invalid block header type")
var PCAPNG_CORRUPTED_FILE = errors.New("file corrupted")
var PCAPNG_SKIPPING_NOT_SUPPORTED = errors.New("skipping not supported")

func alignUint16(i uint16) uint32 {
	return uint32(math.Ceil(float64(i)/4)) * 4
}

func alignUint32(i uint32) uint32 {
	return uint32(math.Ceil(float64(i)/4)) * 4
}

func ByteArrayOption(o *Options, c OptionCode) []byte {
	if o == nil {
		return nil
	}

	values := o.Values[c]

	if len(values) == 0 {
		return nil
	}

	return values[0]
}

func StringOption(o *Options, c OptionCode) string {
	return StringOptionValue(ByteArrayOption(o, c))
}

func StringOptionValue(value []byte) string {
	if value == nil {
		return ""
	}

	//
	// last nil-byte needs to be removed
	//
	l := len(value)

	if l == 0 {
		return ""
	}

	//
	// Trim nil-byte, apple seems to add it
	//
	if value[l-1] == 0 {
		value = value[:l-1]
	}

	return string(value)
}

func timestamp(high, low uint32, ifdb *InterfaceDescriptionBlock) time.Time {
	ts := int64(high)<<32 | int64(low)

	var divisor int64

	tsResol := ifdb.OptionTimestampResolution()
	if tsResol.IsPow10() {
		divisor = int64(math.Pow10(int(tsResol.Value())))
	} else {
		divisor = int64(math.Pow(2, float64(tsResol.Value())))
	}

	seconds := ts / divisor
	microseconds := ts % divisor

	return time.Unix(seconds, microseconds*1000)
}
