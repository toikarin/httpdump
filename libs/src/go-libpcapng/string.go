package pcapng

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

//
// section header
//

func (sh SectionHeaderBlock) String() string {
	optsStr := "<nil>"
	if sh.HasOptions() {
		optsStr = sh.Options.String()
	}

	return fmt.Sprintf(`[SectionHeaderBlock:
  BlockType:     0x%08x
  TotalLength:   %d
  ByteOrder:     %s
  Version:       %d.%d
  SectionLength: %d (skipping supported: %t)
  Options:       %s
]`, sh.BlockType(), sh.TotalLength(), sh.ByteOrder, sh.VersionMajor, sh.VersionMinor, sh.SectionLength,
		sh.SupportsSkipping(), optsStr)
}

func (o SectionHeaderOptions) String() string {
	return fmt.Sprintf(`[SectionHeaderOptions:
    Comment:          %s
    Hardware:         %s
    OS:               %s
    User Application: %s
    Unsupported:      %s
  ]`,
		stringOptVal(o.Comment),
		stringOptVal(o.Hardware),
		stringOptVal(o.OS),
		stringOptVal(o.UserApplication),
		unsupportedOpts(o.Unsupported))
}

//
// enhanced packet
//

func (epb EnhancedPacketBlock) String() string {
	opts := "<nil>"
	if epb.HasOptions() {
		opts = epb.Options.String()
	}

	return fmt.Sprintf(`[EnhancedPacketBlock:
  BlockType:      0x%08x
  TotalLength:    %d
  InterfaceId:    %d
  Timestamp:      %s
  CapturedLength: %d
  PacketLength:   %d
  PacketData:     <byte-array of len: %d>
  Options:        %s
]`, epb.BlockType(), epb.TotalLength(), epb.InterfaceId, epb.Timestamp, epb.CapturedLength, epb.PacketLength, len(epb.PacketData), opts)
}

func (o EnhancedPacketOptions) String() string {
	flagStr := "<nil>"
	hashStr := "<nil>"

	if o.Flags != nil {
		flagStr = o.Flags.String()
	}
	if o.Hash != nil {
		hashStr = o.Hash.String()
	}

	return fmt.Sprintf(`[EnhancedPacketOptions:
    Comment:      %s
    Flags:        %s
    Hash:         %s
    Drop count:   %s
    Unsupported:  %s
  ]`, stringOptVal(o.Comment), flagStr, hashStr, uint64OptVal(o.DropCount), unsupportedOpts(o.Unsupported))
}

func (f PacketFlags) String() string {
	receptionType, promiscuous := f.ReceptionType()

	errors := make([]string, 0)
	if f.ErrorSymbol() {
		errors = append(errors, "symbol")
	}
	if f.ErrorPreamble() {
		errors = append(errors, "preamble")
	}
	if f.ErrorStartFrameDelimiter() {
		errors = append(errors, "startFrameDelimiter")
	}
	if f.ErrorUnalignedFrame() {
		errors = append(errors, "unalignedFrame")
	}
	if f.ErrorWrongInterFrameGap() {
		errors = append(errors, "wrongInterFrameGap")
	}
	if f.ErrorPacketTooShort() {
		errors = append(errors, "packetTooShort")
	}
	if f.ErrorPacketTooLong() {
		errors = append(errors, "packetTooLong")
	}
	if f.ErrorCRC() {
		errors = append(errors, "CRC")
	}

	errorStr := "["
	errorStr += strings.Join(errors, ",")
	errorStr += "]"

	return fmt.Sprintf("[Direction: %s, Reception type: %s (promiscuous: %t), FCS length: %d, errors: %s]",
		f.Direction().String(),
		receptionType.String(),
		promiscuous,
		f.FCSLength(),
		errorStr,
	)
}

func (d PacketFlagDirection) String() string {
	switch d {
	case DIRECTION_NOT_AVAILABLE:
		return "not available"
	case DIRECTION_INBOUND:
		return "inbound"
	case DIRECTION_OUTBOUND:
		return "outbound"
	default:
		panic("should not be here")
	}
}

func (d PacketFlagReceptionType) String() string {
	switch d {
	case RECEPTION_TYPE_UNSPECIFIED:
		return "unspecified"
	case RECEPTION_TYPE_UNICAST:
		return "unicast"
	case RECEPTION_TYPE_MULTICAST:
		return "multicast"
	case RECEPTION_TYPE_BROADCAST:
		return "broadcast"
	default:
		panic("should not be here")
	}
}

func (h PacketHash) String() string {
	return fmt.Sprintf("[Type: %s, len: %d]", h.Algorithm().String(), len(h.Hash()))
}

func (a PacketHashAlgorithm) String() string {
	switch a {
	case PACKET_HASH_2S_COMPLEMENT:
		return "2s_complement"
	case PACKET_HASH_XOR:
		return "XOR"
	case PACKET_HASH_CRC32:
		return "CRC32"
	case PACKET_HASH_MD5:
		return "MD5"
	case PACKET_HASH_SHA1:
		return "SHA1"
	case PACKET_HASH_UNKNOWN:
		return "unknown"
	default:
		panic("should not be here")
	}
}

//
// interface description
//

func (ifdb InterfaceDescriptionBlock) String() string {
	var opts string
	if ifdb.Options != nil {
		opts = ifdb.Options.String()
	} else {
		opts = "<nil>"
	}

	return fmt.Sprintf(`[InterfaceDescriptionBlock:
  BlockType:   0x%08x
  TotalLength: %d
  LinkType:    %d
  SnapLength:  %d
  Options:     %s
]`, ifdb.BlockType(), ifdb.TotalLength(), ifdb.LinkType, ifdb.SnapLength, opts)
}

func (o InterfaceDescriptionOptions) String() string {
	return fmt.Sprintf(`[InterfaceDescriptionOptions:
    Comment:              %s
    Name:                 %s
    Description:          %s
    IPv4 address:         FIXME %s
    IPv6 address:         FIXME %s
    MAC address:          FIXME %s
    EUI address:          FIXME %s
    Speed:                %s
    Timestamp Resolution: %s
    Timezone:             FIXME %s
    Filter:               %s
    OS:                   %s
    FCS length:           %s
    Timestamp Offset:     %s
    Unsupported options:  %s
  ]`,
		stringOptVal(o.Comment),
		stringOptVal(o.Name),
		stringOptVal(o.Description),
		o.IPv4Address,
		o.IPv6Address,
		o.MacAddress,
		o.EUIAddress,
		speedOptVal(o.Speed),
		timestampResolutionOptVal(o.TimestampResolution),
		o.Timezone,
		captureFilterOptVal(o.Filter),
		stringOptVal(o.OS),
		uint8OptVal(o.FCSLength),
		uint64OptVal(o.TimestampOffset),
		unsupportedOpts(o.Unsupported))
}

func speedOptVal(s *uint64) string {
	if s == nil {
		return "<nil>"
	}

	units := []string{"bps", "kpbs", "Mbps", "Gbps"}

	speed := *s
	i := 0
	for {
		if speed < 1000 || i+1 >= len(units) {
			break
		}

		speed = speed / 1000
		i += 1
	}

	return fmt.Sprintf("%d %s", speed, units[i])
}

func timestampResolutionOptVal(tsResol *TimestampResolution) string {
	if tsResol == nil {
		return "<nil>"
	}

	return fmt.Sprintf("[Power of 10: %t, value: %d]", tsResol.IsPow10(), tsResol.Value())
}

func captureFilterOptVal(cf *CaptureFilter) string {
	if cf == nil {
		return "<nil>"
	}

	return fmt.Sprintf("[Filter Code: %d, Details: %s]", cf.Code, cf.Details)
}

//
// process information
//

func (pib ProcessInformationBlock) String() string {
	opts := "<nil>"
	if pib.HasOptions() {
		opts = pib.Options.String()
	}

	return fmt.Sprintf(`[ProcessInformationBlock:
  BlockType:   0x%08x
  TotalLength: %d
  ProcessId:   %d
  Options:     %s
]`, pib.BlockType(), pib.TotalLength(), pib.ProcessId, opts)
}

func (o ProcessInformationOptions) String() string {
	return fmt.Sprintf(`[ProcessInformationOptions
    Comment:      %s
    Process Name: %s
    Unsupported:  %s
  ]`,
		stringOptVal(o.Comment),
		stringOptVal(o.ProcessName),
		unsupportedOpts(o.Unsupported))
}

//
// interface statistics
//

func (ifsb InterfaceStatisticsBlock) String() string {
	opts := "<nil>"
	if ifsb.HasOptions() {
		opts = ifsb.Options.String()
	}

	return fmt.Sprintf(`[InterfaceStatisticsBlock:
  BlockType:      0x%08x
  TotalLength:    %d
  InterfaceId:    %d
  Interface:      %s
  Timestamp:      %s
  Options:        %s
]`, ifsb.BlockType(), ifsb.TotalLength(), ifsb.InterfaceId, ifsb.Interface.OptionName(), ifsb.Timestamp, opts)
}

func (o InterfaceStatisticsOptions) String() string {
	return fmt.Sprintf(`[InterfaceStatisticsOptions:
    Comment:      %s
    StartTime:    %s
    EndTime:      %s
    IfRecv:       %s
    IfDrop:       %s
    FilterAccept: %s
    OsDrop:       %s
    UsrDeliv:     %s
    Unsupported:  %s
  ]`,
		stringOptVal(o.Comment),
		timeOptVal(o.StartTime),
		timeOptVal(o.EndTime),
		uint16OptVal(o.IfRecv),
		uint16OptVal(o.IfDrop),
		uint16OptVal(o.FilterAccept),
		uint16OptVal(o.OsDrop),
		uint16OptVal(o.UsrDeliv),
		unsupportedOpts(o.Unsupported))
}

//
// name resolution block
//

func (nrb NameResolutionBlock) String() string {
	opts := "<nil>"
	if nrb.HasOptions() {
		opts = nrb.Options.String()
	}

	ipv4records := ""
	for i, r := range nrb.IPv4Records {
		if i > 0 {
			ipv4records += "\n"
		}

		ipv4records += "    " + r.String()
	}

	ipv6records := ""
	for i, r := range nrb.IPv6Records {
		if i > 0 {
			ipv6records += "\n"
		}

		ipv6records += "    " + r.String()
	}

	return fmt.Sprintf(`[NameResolutionBlock:
  BlockType:         0x%08x
  TotalLength:       %d
  IPv4 Records (%d): [
%s
]
  IPv6 Records (%d): [
%s
]
  Options:           %s
]`, nrb.BlockType(), nrb.TotalLength(), len(nrb.IPv4Records), ipv4records, len(nrb.IPv6Records), ipv6records, opts)
}

func (o NameResolutionOptions) String() string {
	return fmt.Sprintf(`[NameResolutionOption:
    Comment:      %s
    DnsName:      %s
    IPv4 Address: %s
    IPv6 Address: %s
    Unsupported:  %s
  ]`,
		stringOptVal(o.Comment),
		stringOptVal(o.DnsName),
		ipv4OptVal(o.IPv4Address),
		ipv6OptVal(o.IPv6Address),
		unsupportedOpts(o.Unsupported))
}

func ipv4OptVal(a *IPv4Address) string {
	if a == nil {
		return "<nil>"
	}

	return fmt.Sprintf("%d.%d.%d.%d", a[0], a[1], a[2], a[3])
}

func ipv6OptVal(a *IPv6Address) string {
	if a == nil {
		return "<nil>"
	}

	s := ""

	for i, part := range a {
		if i > 0 {
			s += ":"
		}

		s += fmt.Sprintf("%x", part)
	}

	return s
}

//
// helpers
//

func uint8OptVal(u *uint8) string {
	if u == nil {
		return "<nil>"
	}

	return strconv.FormatInt(int64(*u), 10)
}

func uint16OptVal(u *uint16) string {
	if u == nil {
		return "<nil>"
	}

	return strconv.FormatInt(int64(*u), 10)
}

func uint32OptVal(u *uint32) string {
	if u == nil {
		return "<nil>"
	}

	return strconv.FormatInt(int64(*u), 10)
}

func uint64OptVal(u *uint64) string {
	if u == nil {
		return "<nil>"
	}

	return strconv.FormatInt(int64(*u), 10)
}

func timeOptVal(t *time.Time) string {
	if t == nil {
		return "<nil>"
	}

	return t.String()
}

func stringOptVal(s *string) string {
	if s == nil {
		return "<nil>"
	}

	return *s
}

func (a IPv4Record) String() string {
	return fmt.Sprintf("%d.%d.%d.%d = %s", a.Address[0], a.Address[1], a.Address[2], a.Address[3], a.Name)
}

func (a IPv6Record) String() string {
	s := ""

	for i, part := range a.Address {
		if i > 0 {
			s += ":"
		}

		s += fmt.Sprintf("%x", part)
	}

	s += " = " + a.Name

	return s
}

func unsupportedOpts(o map[OptionCode][]OptionValue) string {
	if len(o) == 0 {
		return "<nil>"
	}

	s := ""

	for k, _ := range o {
		if s != "" {
			s += ", "
		}

		s += strconv.Itoa(int(k))
	}

	return "[" + s + "]"
}
