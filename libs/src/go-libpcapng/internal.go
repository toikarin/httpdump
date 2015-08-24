package pcapng

import (
	"math"
	"time"
)

func alignUint16(i uint16) uint32 {
	return uint32(math.Ceil(float64(i)/4)) * 4
}

func alignUint32(i uint32) uint32 {
	return uint32(math.Ceil(float64(i)/4)) * 4
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
