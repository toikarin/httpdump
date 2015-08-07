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

	if pcapPacketHeader != nil {}

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
	// only handle ipv4
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
	// 1. Read ethernet frame header
	//
	ethernetFrameHeader, err := NewEthernetFrameHeader(packetData)
	if err != nil {
		return err
	}

	packetData = packetData[ETHERNET_FRAME_HEADER_LENGTH:]

	//
	// 2. Read network layer frame header
	//
	ipFrameHeader, err := readNetworkLayer(packetData, ethernetFrameHeader.Type())
	if err != nil { return err }
	if ipFrameHeader == nil { return nil }

	packetData = packetData[ipFrameHeader.HeaderLength():]

	if ipFrameHeader.Protocol() != PROTOCOL_TCP {
		switch ipFrameHeader.Protocol() {
		case PROTOCOL_UDP:
			fmt.Println("udp frame skipped")
		case PROTOCOL_ICMP:
			fmt.Println("icmp frame skipped")
		default:
			fmt.Println("unknown frame skipped")
		}

		return nil
	}

	//
	// 3. Read TCP frame header
	//
	tcpFrameHeader, err := NewTcpFrameHeader(packetData)
	if err != nil {
		return err
	}

	packetData = packetData[TCP_FRAME_HEADER_LENGTH:]

	// Read TCP options
	tcpOptsLen := tcpFrameHeader.OptionsLength()
	if tcpOptsLen > 0 {
		packetData = packetData[tcpOptsLen:]
	}

	//
	// 4. Read TCP payload
	//
	payloadLen := uint32(ipFrameHeader.TotalLength()-uint16(ipFrameHeader.HeaderLength())) - uint32(tcpFrameHeader.DataOffset())

	if payloadLen > 0 {
		payload := packetData[:payloadLen]

		// GET
		if isHttpReq(payload) {
			fmt.Print(green("> " + string(payload)))
		}
	}

	if true {
		fmt.Println(ethernetFrameHeader)
		fmt.Println(ipFrameHeader)
		fmt.Println(tcpFrameHeader)
		fmt.Println("Payload length:", payloadLen)
		fmt.Println("-----------------------")
	}

	if true {
		fmt.Printf("IPv%d, TCP %s, payload len: %d\n", ipFrameHeader.Version(), flagString(*tcpFrameHeader), payloadLen)
	}

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
