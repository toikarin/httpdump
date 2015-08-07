package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) > 1 {
		// Read from file
		f, err := os.Open(os.Args[1])
		if err != nil {
			panic(err)
		}

		readStream(f)
	} else {
		// Read from stdin
		readStream(os.Stdin)
	}
}

func readStream(r io.Reader) {
	pcapFileHeader, err := readPcapFileHeader(r)
	if err != nil {
		if err == io.EOF {
			return
		}
		panic(err)
	}

	for {
		err = readPacket(r, pcapFileHeader.ByteOrder)
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
	}
}

func readPacket(r io.Reader, bo binary.ByteOrder) error {
	//
	// Read pcap packet header
	//
	pcapPacketHeader, err := readPcapPacketHeader(r, bo)
	if err != nil {
		return err
	}

	//
	// Read rest of the packet
	//
	packetData, err := readPacketData(r, pcapPacketHeader.IncludeLength())
	if err != nil {
		return err
	}

	return readEthernetPacket(packetData)
}

type NetworkLayerFrame interface {
	Version() uint8
	Protocol() uint8
	HeaderLength() uint8
	TotalLength() uint16
}

func readNetworkLayer(data []byte, layerType uint16) (NetworkLayerFrame, error) {
	switch layerType {
	case ETHERTYPE_IPV4:
		return NewIPv4FrameHeader(data)
	case ETHERTYPE_IPV6:
		return NewIPv6FrameHeader(data)
	default:
		return nil, nil
	}
}

func readEthernetPacket(packetData []byte) error {
	//
	// Read ethernet frame header
	//
	ethernetFrameHeader, err := NewEthernetFrameHeader(packetData)
	if err != nil {
		return err
	}

	packetData = packetData[ETHERNET_FRAME_HEADER_LENGTH:]

	//
	// Read network layer frame header
	//
	ipFrameHeader, err := readNetworkLayer(packetData, ethernetFrameHeader.Type())
	if err != nil {
		return err
	}
	if ipFrameHeader == nil {
		return nil
	}

	packetData = packetData[ipFrameHeader.HeaderLength():]

	switch ipFrameHeader.Protocol() {
	case PROTOCOL_TCP:
		return handleTCP(packetData, ipFrameHeader)
	case PROTOCOL_UDP:
		return handleUDP(packetData, ipFrameHeader)
	case PROTOCOL_ICMP:
		return handleICMP(packetData, ipFrameHeader)
	default:
		fmt.Println("unknown frame skipped")
	}

	return nil
}

func handleUDP(packetData []byte, ipFrameHeader NetworkLayerFrame) error {
	udpFrameHeader, err := NewUDPFrameHeader(packetData)
	if err != nil {
		return err
	}

	packetData = packetData[UDP_FRAME_HEADER_LENGTH:]
	payloadLen := udpFrameHeader.Length() - UDP_FRAME_HEADER_LENGTH

	//
	// Log packet
	//
	fmt.Printf("%15s:%-5d -> %15s:%-5d: IPv%d, UDP, payload len: %d\n", sourceAddressToString(ipFrameHeader),
		udpFrameHeader.SourcePort(), destinationAddressToString(ipFrameHeader),
		udpFrameHeader.DestinationPort(), ipFrameHeader.Version(), payloadLen)

	return nil
}

func handleICMP(packetData []byte, ipFrameHeader NetworkLayerFrame) error {
	icmpFrameHeader, err := NewICMPFrameHeader(packetData)
	if err != nil {
		return err
	}

	packetData = packetData[ICMP_FRAME_HEADER_LENGTH:]

	//
	// Log packet
	//
	fmt.Printf("%15s -> %15s: ICMP Type %d\n", sourceAddressToString(ipFrameHeader),
		destinationAddressToString(ipFrameHeader), icmpFrameHeader.Type())

	return nil
}

func handleTCP(packetData []byte, ipFrameHeader NetworkLayerFrame) error {
	//
	// Read TCP header
	//
	tcpFrameHeader, err := NewTcpFrameHeader(packetData)
	if err != nil {
		return err
	}

	packetData = packetData[TCP_FRAME_HEADER_LENGTH:]

	//
	// Read TCP options
	//
	tcpOptsLen := tcpFrameHeader.OptionsLength()
	if tcpOptsLen > 0 {
		packetData = packetData[tcpOptsLen:]
	}

	//
	// Read TCP payload
	//
	payloadLen := uint32(ipFrameHeader.TotalLength()-uint16(ipFrameHeader.HeaderLength())) - uint32(tcpFrameHeader.DataOffset())

	if payloadLen > 0 {
		payload := packetData[:payloadLen]

		// GET
		if isHttpReq(payload) && false {
			fmt.Print(green("> " + string(payload)))
		}
	}

	//
	// Log packet
	//
	fmt.Printf("%15s:%-5d -> %15s:%-5d: IPv%d, TCP [%7s], payload len: %d\n",
		sourceAddressToString(ipFrameHeader), tcpFrameHeader.SourcePort(),
		destinationAddressToString(ipFrameHeader), tcpFrameHeader.DestinationPort(),
		ipFrameHeader.Version(), flagString(*tcpFrameHeader), payloadLen)

	return nil
}

func isHttpReq(data []byte) bool {
	return data[0] == 71 && data[1] == 69 && data[2] == 84 // GET, FIXME
}

func red(s string) string {
	return "\033[31m" + s + "\033[0m"
}

func blue(s string) string {
	return "\033[94m" + s + "\033[0m"
}

func green(s string) string {
	return "\033[92m" + s + "\033[0m"
}

func sourceAddressToString(a interface{}) string {
	switch t := a.(type) {
	case *IPv4FrameHeader:
		return IPv4String(a.(*IPv4FrameHeader).SourceAddress())
	case *IPv6FrameHeader:
		return IPv6String(a.(*IPv6FrameHeader).SourceAddress())
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func destinationAddressToString(a interface{}) string {
	switch t := a.(type) {
	case *IPv4FrameHeader:
		return IPv4String(a.(*IPv4FrameHeader).DestinationAddress())
	case *IPv6FrameHeader:
		return IPv6String(a.(*IPv6FrameHeader).DestinationAddress())
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}
