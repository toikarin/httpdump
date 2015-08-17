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
		pcapPacketHeader, linkLayer, networkLayer, transportLayer, err := readPacket(r, pcapFileHeader.ByteOrder)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		packetListener.NewPacket(*pcapFileHeader, *pcapPacketHeader, linkLayer, networkLayer, transportLayer)
	}
}

func readPacket(r io.Reader, bo binary.ByteOrder) (pcapPacketHeader *PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}, err error) {
	//
	// Read pcap packet header
	//
	pcapPacketHeader, err = readPcapPacketHeader(r, bo)
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
	// Read ethernet packet
	//
	linkLayer, networkLayer, transportLayer, err = readEthernetPacket(packetData)
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

func readEthernetPacket(packetData []byte) (linkLayer, networkLayer, transportLayer interface{}, err error) {
	var protocol uint8
	var payload []byte
	var networkFrame interface{}

	//
	// Read ethernet frame
	//
	ethernetFrame, err := NewEthernetFrame(packetData)
	if err != nil {
		return nil, nil, nil, err
	}
	if ethernetFrame == nil {
		return nil, nil, nil, nil
	}

	//
	// Read network frame
	//
	switch ethernetFrame.Header.Type() {
	case ETHERTYPE_IPV4:
		ipv4Frame, err := NewIPv4Frame(ethernetFrame.Payload)
		if err != nil {
			return ethernetFrame, nil, nil, err
		}

		networkFrame = ipv4Frame
		payload = ipv4Frame.Payload
		protocol = ipv4Frame.Header.Protocol()
	case ETHERTYPE_IPV6:
		ipv6Frame, err := NewIPv6Frame(ethernetFrame.Payload)
		if err != nil {
			return ethernetFrame, nil, nil, err
		}

		networkFrame = ipv6Frame
		payload = ipv6Frame.Payload
		protocol = ipv6Frame.Header.Protocol()
	default:
		// unknown network layer
		readdebug(fmt.Sprintf("Unsupported network layer of type %d [%s].",
			ethernetFrame.Header.Type(), EtherTypeToString(ethernetFrame.Header.Type())))
		return ethernetFrame, nil, nil, nil
	}

	//
	// Read transport frame
	//
	switch protocol {
	case PROTOCOL_TCP:
		tcpFrame, err := NewTCPFrame(payload)
		return ethernetFrame, networkFrame, tcpFrame, err
	case PROTOCOL_UDP:
		udpFrame, err := NewUDPFrame(payload)
		return ethernetFrame, networkFrame, udpFrame, err
	case PROTOCOL_ICMP:
		icmpFrame, err := NewICMPFrame(payload)
		return ethernetFrame, networkFrame, icmpFrame, err
	default:
		// unknown transport layer
		readdebug(fmt.Sprintf("Unsupported transport layer of protocol %d [%s].",
			protocol, IpProtocolToString(protocol)))
		return ethernetFrame, networkFrame, nil, nil
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
