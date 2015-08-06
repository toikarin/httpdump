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
	// 1. Read pcap packet header
	//
	pcapPacketHeader, err := readPcapPacketHeader(r, bo)
	if err != nil {
		return err
	}

	if pcapPacketHeader != nil {
	}
	fmt.Println(pcapPacketHeader)

	pcapPacketDataLeft := pcapPacketHeader.IncludeLength()

	//
	// 2. Read ethernet frame header
	//
	ethernetFrameHeader, err := readEthernetFrameHeader(r)
	if err != nil {
		return err
	}

	if ethernetFrameHeader != nil {
	}
	fmt.Println(ethernetFrameHeader)

	pcapPacketDataLeft -= ETHERNET_FRAME_HEADER_LENGTH

	// only handle ipv4
	if ethernetFrameHeader.Type() != ETHERTYPE_IPV4 {
		fmt.Println("Unknown ethernet packet type:", ethernetFrameHeader.Type())

		_, err := readPacketData(r, pcapPacketDataLeft)
		if err != nil {
			return err
		}

		return nil
	}

	//
	// 3. Read IPv4 frame header
	//
	ipv4FrameHeader, err := readIPv4FrameHeader(r)
	fmt.Println(ipv4FrameHeader)
	if err != nil {
		return err
	}

	pcapPacketDataLeft -= IPV4_FRAME_HEADER_LEN

	if ipv4FrameHeader.Protocol() != PROTOCOL_TCP {
		fmt.Println("invalid protocol:", ipv4FrameHeader.Protocol())

		_, err := readPacketData(r, pcapPacketDataLeft)
		if err != nil {
			return err
		}

		return nil
	}

	//
	// 4. Read TCP frame header
	//
	tcpFrameHeader, err := readTcpFrameHeader(r)
	fmt.Println(tcpFrameHeader)
	if err != nil {
		return err
	}

	// Read TCP options
	err = readTcpOptions(r, tcpFrameHeader.OptionsLength())
	if err != nil {
		return err
	}

	pcapPacketDataLeft -= TCP_FRAME_HEADER_LENGTH + uint32(tcpFrameHeader.OptionsLength())

	//
	// 5. Read TCP payload
	//
	payloadLen := uint32(ipv4FrameHeader.TotalLength()-uint16(ipv4FrameHeader.HeaderLength())) - uint32(tcpFrameHeader.DataOffset())

	if payloadLen > 0 {
		data, err := readPacketData(r, uint32(payloadLen))
		if err != nil {
			return err
		}

		pcapPacketDataLeft -= payloadLen

		// GET
		if isHttpReq(data) {
			fmt.Print(green("> " + string(data)))
		}
		// HTTP/1.0 or HTTP/1.1
		/*} else if data[0] == 72 && data[1] == 84 && data[2] == 84 && data[3] == 80 && data[4] == 47 && data[5] == 49 && data[6] == 46 && (data[7] == 48 || data[7] == 49) {
			fmt.Print(red("< " + string(data)))
		} else {
			fmt.Println("Unknown data of length", dataLeft)
		}
		*/
	}

	//
	// 6. Read (optional) padding data
	//
	if pcapPacketDataLeft > 0 {
		_, err := readPacketData(r, pcapPacketDataLeft)
		if err != nil {
			return err
		}
	}

	if false {
		fmt.Println(pcapPacketHeader)
		fmt.Println(ethernetFrameHeader)
		fmt.Println(ipv4FrameHeader)
		fmt.Println(tcpFrameHeader)
		fmt.Println("Payload length:", payloadLen)
		fmt.Println("-----------------------")
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
