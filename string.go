package main

import (
	"fmt"
	"strconv"
)

func binarystr(i int64) string {
	return strconv.FormatInt(i, 2)
}

func (p PcapPacketHeader) String() string {
	return fmt.Sprintf(`[PcapPacketHeader:
  Timestamp:      %s
  OriginalLength: %d
  IncludeLength:  %d
]`, p.Timestamp(), p.OriginalLength(), p.IncludeLength())
}

func MacString(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func etherType(t uint16) string {
	switch t {
	case ETHERTYPE_IPV4:
		return "IPv4"
	case ETHERTYPE_IPV6:
		return "IPv6"
	default:
		return "unknown"
	}
}

func (p EthernetFrameHeader) String() string {
	return fmt.Sprintf(`[EthernetFrameHeader:
  SourceMac:      %s
  DestinationMac: %s
  Type:           0x%x (%s)
]`, MacString(p.Destination()), MacString(p.Source()), p.Type(), etherType(p.Type()))
}

func IPv4String(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", a>>24, (a&0xFF0000)>>16, (a&0xFF00)>>8, (a & 0xFF))
}

func protocol(p uint8) string {
	switch p {
	case PROTOCOL_TCP:
		return "tcp"
	case PROTOCOL_UDP:
		return "udp"
	case PROTOCOL_ICMP:
		return "icmp"
	default:
		return "unknown"
	}
}

func (p IPv4FrameHeader) String() string {
	return fmt.Sprintf(`[IPv4FrameHeader:
  Version:             %d
  HeaderLength:        %d
  DSCP:                %d
  ECN:                 %d
  TotalLength:         %d
  Identification:      %d
  Flags:               0b%03s [DontFragment: %t, MoreFragments: %t]
  FragmentOffset:      %d
  TimeToLive:          %d
  Protocol:            %d (%s)
  Source Address:      %s
  Destination Address: %s
]`, p.Version(), p.HeaderLength(), p.DSCP(), p.ECN(), p.TotalLength(), p.Identification(), binarystr(int64(p.Flags())), p.DontFragment(), p.MoreFragments(),
		p.FragmentOffset(), p.TimeToLive(), p.Protocol(), protocol(p.Protocol()), IPv4String(p.SourceAddress()), IPv4String(p.DestinationAddress()))
}

func flagString(h TcpFrameHeader) string {
	s := ""

	if h.FlagNS() {
		s = appendFlagString(s, "NS")
	}
	if h.FlagCWR() {
		s = appendFlagString(s, "CWR")
	}
	if h.FlagECE() {
		s = appendFlagString(s, "ECE")
	}
	if h.FlagURG() {
		s = appendFlagString(s, "URG")
	}
	if h.FlagACK() {
		s = appendFlagString(s, "ACK")
	}
	if h.FlagPSH() {
		s = appendFlagString(s, "PSH")
	}
	if h.FlagRST() {
		s = appendFlagString(s, "RST")
	}
	if h.FlagSYN() {
		s = appendFlagString(s, "SYN")
	}
	if h.FlagFIN() {
		s = appendFlagString(s, "FIN")
	}

	return s
}

func appendFlagString(s1, s2 string) string {
	if s1 != "" {
		s1 += ","
	}

	return s1 + s2
}

func (p TcpFrameHeader) String() string {
	return fmt.Sprintf(`[TcpFrameHeader:
  SourcePort:         %d
  DestinationPort:    %d
  Sequence Number:    %d
  Acknowledge Number: %d
  Data offset:        %d (Options length: %d)
  Flags:              0b%09s [%s]
  Window Size:        %d
  Checksum:           %d
  UrgentPointer:      %d
]`, p.SourcePort(), p.DestinationPort(), p.SequenceNumber(), p.AcknowledgeNumber(), p.DataOffset(),
		p.OptionsLength(), binarystr(int64(p.Flags())), flagString(p), p.WindowSize(), p.Checksum(), p.UrgentPointer())
}
