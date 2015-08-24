package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

type PacketListener interface {
	NewPacket(fileHeader PcapFileHeader, ipacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{})
}

func readStream(r io.Reader, packetListener PacketListener) error {
	pcapFileHeader, err := readPcapFileHeader(r)
	if err != nil {
		if err == io.EOF {
			return nil
		}

		return err
	}

	for {
		pcapPacketHeader, linkLayer, networkLayer, transportLayer, err := readPacket(r, pcapFileHeader)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		packetListener.NewPacket(*pcapFileHeader, *pcapPacketHeader, linkLayer, networkLayer, transportLayer)
	}
}

func readPacket(r io.Reader, pcapFileHeader *PcapFileHeader) (pcapPacketHeader *PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}, err error) {
	//
	// Read pcap packet header
	//
	pcapPacketHeader, err = readPcapPacketHeader(r, pcapFileHeader.ByteOrder)
	if err != nil {
		return
	}

	//
	// Read rest of the packet
	//
	packetData, err := read(r, pcapPacketHeader.IncludeLength())
	if err != nil {
		return
	}

	//
	// Read packet
	//
	linkLayer, networkLayer, transportLayer, err = readLayerPacket(pcapFileHeader, packetData)
	return
}

func readPcapFileHeader(r io.Reader) (header *PcapFileHeader, err error) {
	buf, err := read(r, PCAP_FILE_HEADER_LENGTH)
	if err != nil {
		return nil, err
	}

	return NewPcapFileHeader(buf)
}

func readPcapPacketHeader(r io.Reader, bo binary.ByteOrder) (*PcapPacketHeader, error) {
	buf, err := read(r, PCAP_PACKET_HEADER_LENGTH)
	if err != nil {
		return nil, err
	}

	return NewPcapPacketHeader(buf, bo)
}

func readLayerPacket(pcapFileHeader *PcapFileHeader, packetData []byte) (linkLayer, networkLayer, transportLayer interface{}, err error) {
	var protocol uint8
	var payload []byte
	var linkFrame interface{}
	var networkFrame interface{}
	var etherType uint16

	//
	// Read layer frame
	//
	switch pcapFileHeader.Network() {
	case PCAP_LINKTYPE_ETHERNET:
		ethernetFrame, err := NewEthernetFrame(packetData)
		if err != nil {
			return nil, nil, nil, err
		}
		if ethernetFrame == nil {
			return nil, nil, nil, nil
		}

		etherType = ethernetFrame.Header.Type()
		payload = ethernetFrame.Payload
	case PCAP_LINKTYPE_NULL:
		nullFrame, err := NewNullFrame(packetData, pcapFileHeader.ByteOrder)
		if err != nil {
			return nil, nil, nil, err
		}
		if nullFrame == nil {
			return nil, nil, nil, nil
		}

		linkFrame = nullFrame
		payload = nullFrame.Payload

		//
		// Figure out network frame type
		//
		switch nullFrame.LinkType {
		case NULL_FRAME_LINKTYPE_AF_INET:
			etherType = ETHERTYPE_IPV4
		default:
			//
			// ipv6 has multiple values, just try to parse it
			//
			header, _ := NewIPv6FrameHeader(nullFrame.Payload)
			if header != nil {
				etherType = ETHERTYPE_IPV6
			} else {
				//
				// fallback to ipv4 checking
				//
				header, _ := NewIPv4FrameHeader(nullFrame.Payload)
				if header != nil {
					etherType = ETHERTYPE_IPV4
				} else {
					// unknown network layer
					readdebug(fmt.Sprintf("Unsupported lookback of type %d.", nullFrame.LinkType))
					return nullFrame, nil, nil, nil
				}
			}
		}
	default:
		readdebug(fmt.Sprintf("Unsupported network type %d.", network))
		return nil, nil, nil, nil
	}

	//
	// Read network frame
	//
	switch etherType {
	case ETHERTYPE_IPV4:
		ipv4Frame, err := NewIPv4Frame(payload)
		if err != nil {
			return linkFrame, nil, nil, err
		}

		networkFrame = ipv4Frame
		payload = ipv4Frame.Payload
		protocol = ipv4Frame.Header.Protocol()
	case ETHERTYPE_IPV6:
		ipv6Frame, err := NewIPv6Frame(payload)
		if err != nil {
			return linkFrame, nil, nil, err
		}

		networkFrame = ipv6Frame
		payload = ipv6Frame.Payload
		protocol = ipv6Frame.Header.Protocol()
	default:
		// unknown network layer
		readdebug(fmt.Sprintf("Unsupported network layer of type %d [%s].",
			etherType, EtherTypeToString(etherType)))
		return linkFrame, nil, nil, nil
	}

	//
	// Read transport frame
	//
	switch protocol {
	case PROTOCOL_TCP:
		tcpFrame, err := NewTCPFrame(payload)
		return linkFrame, networkFrame, tcpFrame, err
	case PROTOCOL_UDP:
		udpFrame, err := NewUDPFrame(payload)
		return linkFrame, networkFrame, udpFrame, err
	case PROTOCOL_ICMP:
		icmpFrame, err := NewICMPFrame(payload)
		return linkFrame, networkFrame, icmpFrame, err
	default:
		// unknown transport layer
		readdebug(fmt.Sprintf("Unsupported transport layer of protocol %d [%s].",
			protocol, IpProtocolToString(protocol)))
		return linkFrame, networkFrame, nil, nil
	}
}

func read(r io.Reader, len uint32) (data []byte, err error) {
	buf := make([]byte, len)

	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func readdebug(a ...interface{}) {
	if true {
		debug("debug-read:", a...)
	}
}
