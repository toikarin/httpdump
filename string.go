package main

import (
	"fmt"
	"strconv"
)

func binarystr(i int64) string {
	return strconv.FormatInt(i, 2)
}

func MacString(mac []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func EtherTypeToString(t uint16) string {
	switch t {
	case ETHERTYPE_IPV4:
		return "IPv4"
	case ETHERTYPE_IPV6:
		return "IPv6"
	case ETHERTYPE_ARP:
		return "ARP"
	case ETHERTYPE_LLDP:
		return "LLDP"
	default:
		return "unknown"
	}
}

func (f EthernetFrame) String() string {
	return fmt.Sprintf(`[EthernetFrame:
  Header:         %s
  Payload Length: %d
]`, f.Header, len(f.Payload))
}

func (p EthernetFrameHeader) String() string {
	return fmt.Sprintf(`[EthernetFrameHeader:
  SourceMac:      %s
  DestinationMac: %s
  Type:           0x%x (%s)
]`, MacString(p.Destination()), MacString(p.Source()), p.Type(), EtherTypeToString(p.Type()))
}

func AddressToString(a interface{}) string {
	switch t := a.(type) {
	case uint32:
		return IPv4String(a.(uint32))
	case IPv6Address:
		return IPv6String(a.(IPv6Address))
	default:
		panic(fmt.Sprintf("Unknown address type: %T", t))
	}
}

func IPv4String(a uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", a>>24, (a&0xFF0000)>>16, (a&0xFF00)>>8, (a & 0xFF))
}

func IPv6String(a IPv6Address) string {
	longest, longestIdx := -1, -1
	curStreak, curIdx := -1, -1

	// find longest streak of zeros to convert
	for i, part := range a {
		if part == 0 {
			// do we start a new streak?
			if curStreak == -1 {
				curIdx = i
				curStreak = 1
			} else {
				// streak continues
				curStreak += 1

				if curStreak > longest {
					longest = curStreak
					longestIdx = curIdx
				}
			}
		} else {
			curStreak, curIdx = -1, -1
		}
	}

	s := ""

	for i := 0; i < 8; {
		if i == longestIdx {
			s += ":"
			i += longest

			// add last colon
			if i == 8 {
				s += ":"
			}
		} else {
			if i != 0 {
				s += ":"
			}

			s += fmt.Sprintf("%x", a[i])

			i += 1
		}
	}

	return s
}

func IpProtocolToString(p uint8) string {
	switch p {
	case PROTOCOL_TCP:
		return "tcp"
	case PROTOCOL_UDP:
		return "udp"
	case PROTOCOL_ICMP:
		return "icmp"
	case PROTOCOL_IGMP:
		return "igmp"
	case PROTOCOL_ICMP_V6:
		return "icmp for IPv6"
	case PROTOCOL_HOPOPT:
		return "IPv6 Hop-by-Hop Option"
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
		p.FragmentOffset(), p.TimeToLive(), p.Protocol(), IpProtocolToString(p.Protocol()), IPv4String(p.SourceAddress()), IPv4String(p.DestinationAddress()))
}

func (p IPv6FrameHeader) String() string {
	return fmt.Sprintf(`[IPv6FrameHeader:
  Version:             %d
  TrafficClass:        %d
  FlowControl:         %d
  Payload Length:      %d
  NextHeader:          %d
  Hop Limit:           %d
  Source Address:      %s
  Destination Address: %s
]`, p.Version(), p.TrafficClass(), p.FlowControl(), p.PayloadLength(), p.NextHeader(), p.HopLimit(),
		IPv6String(p.SourceAddress()), IPv6String(p.DestinationAddress()))
}

func flagString(h TCPFrameHeader) string {
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

func (p TCPFrameHeader) String() string {
	return fmt.Sprintf(`[TCPFrameHeader:
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
