package main

import (
	//	"encoding/binary"
	"fmt"
	"go-libpcapng"
	"io"
)

type PacketListener interface {
	NewPacket(fileHeader PcapFileHeader, ipacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{})
}

func readStream(r io.Reader, packetListener PacketListener) error {
	stream := pcapng.NewStream(r)

	for {
		block, err := stream.NextBlock()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}

		fmt.Println(block)

		switch block.(type) {
		case *pcapng.InterfaceStatisticsBlock:
		}
	}

	return nil
}

/*
func NewPcapngBlockHeader(data []byte) (*PcapngBlockHeader, error) {
	if len(data) != 8 {
		return nil, errors.New("FIXME")
	}

	return &PcapngBlockHeader{data}
}
*/

/*
type ParsedSectionHeader type {
	header *BlockHeader
	body *BlockBody
	opts []BlockOptions
}
*/

/*
func readPcapngStream(r io.Reader) error {
	//
	// initial section header block read
	//

	//
	// Read block header
	//
	headerBuf, err := read(r, 24)

	switch err {
	case io.EOF:
		return nil
	case io.ErrUnexpectedEOF:
		//
		// on first try it's ok if we don't have enough data (assume this is not pcapng stream).
		//
		return nil
	}

	blockHeader, err := NewPcapngBlockHeader(headerBuf)
	if err != nil {
		return err
	}

	//
	// Check block type matches to section header
	//
	if blockHeader.BlockType() != PCAP_NG_BLOCK_TYPE_SECTION_HEADER {
		return nil
	}

	//
	// Parse body
	//
	sectionHeaderBody, err := NewPcapngSectionHeader(headerBuf[8:])
	if err != nil {
		return err
	}

	//
	// Read options
	//
	optsLen := header.TotalLength() - 28 // 12 + 16
	opts, err = readOptions(r, header.ByteOrder, optsLen)
	if err != nil {
		return err
	}

	//
	// Read last block total length
	//
	_, err = readExactly(r, 4)
	if err != nil {
		return err
	}

	section := SectionHeader{blockHeader, sectionHeaderBody, opts}

	//
	// handle rest of the blocks
	//
	for {
		//
		// Read block header
		//
		headerBuf, err := read(r, 8)
		if err != nil {
			if err == io.EOF {
				return nil
			}

			return err
		}

		blockHeader, err := NewPcapngBlockHeader(headerBuf)
		if err != nil {
			return err
		}

		switch blockHeader.BlockType() {
		}
	}
}

/*
func readStream(r io.Reader, packetListener PacketListener) error {
	pcapNgFileHeader, opts, err := readPcapngFileHeader(r)

	if err != nil {
		if err == io.EOF {
			return nil
		}

		return err
	}

	fmt.Println(pcapNgFileHeader)
	fmt.Println(String(opts, pcapNgFileHeader.BlockType(), pcapNgFileHeader.ByteOrder))

	for {
		buf, err := read(r, 8)
		if err != nil {
			if err == io.EOF {
				fmt.Println("EOF")
				return nil
			}

			return err
		}

		blockType := pcapNgFileHeader.ByteOrder.Uint32(buf[0:4])
		blockTotalLen := pcapNgFileHeader.ByteOrder.Uint32(buf[4:8])
		restBlockData, err := read(r, alignUint32(blockTotalLen - 8))
		block := PcapngBlock{pcapNgFileHeader.ByteOrder, append(buf, restBlockData...)}

		switch blockType {
		case PCAP_NG_BLOCK_TYPE_EXPERIMENTAL_PROCESS_INFORMATION:
			procInfo, opts, err := NewPcapngProcessInformation(&block)
			if false {
				fmt.Println("processInfo")
				fmt.Println(procInfo)
				fmt.Println(String(opts, block.BlockType(), pcapNgFileHeader.ByteOrder))
				fmt.Println(err)
			}
		case PCAP_NG_BLOCK_TYPE_INTERFACE_DESC:
			if false {
				ifdesc, opts, err := NewPcapngInterfaceDescription(&block)
				fmt.Println("if")
				fmt.Println(ifdesc)
				fmt.Println(String(opts, block.BlockType(), pcapNgFileHeader.ByteOrder))
				fmt.Println(err)
			}
		case PCAP_NG_BLOCK_TYPE_ENHANCED_PACKET:
			if false {
				epacket, opts, err := NewPcapngEnhancedPacket(&block)
				fmt.Println("epacket")
				fmt.Println(epacket)
				fmt.Println(String(opts, block.BlockType(), pcapNgFileHeader.ByteOrder))
				fmt.Println(err)
		}
		case PCAP_NG_BLOCK_TYPE_SECTION_HEADER:
			fmt.Println("NEW SEC")
		default:
			fmt.Println(binary.LittleEndian.Uint32(buf[0:4]))
			fmt.Println(binary.BigEndian.Uint32(buf[0:4]))
			fmt.Println("not handled", blockType)
		}
	}

	if pcapNgFileHeader != nil {
		return errors.New("pcap-ng not supported")
	}

	if err != nil {
		if err == io.EOF {
			return nil
		}

		return err
	}

	return nil
}
*/

/*
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

/*
func readBlock(r io.Reader, bo binary.ByteOrder) error {
	/*
	buf, err := read(r, 8)
	if err != nil {
		return err
	}

	blockType := bo.Uint32(buf[0:4])
	blockTotalLen := bo.Uint32(buf[4:8])

	blockData, err := read(r, blockTotalLen - 8)
	if err != nil {
		return err
	}

	var blockBodyLen uint32
	switch blockType {
	case PCAP_NG_BLOCK_TYPE_INTERFACE_DESC:
		blockBodyLen = PCAP_NG_BLOCK_BODY_LEN_INTERFACE_DESC
	case PCAP_NG_BLOCK_TYPE_SECTION_HEADER:
		blockBodyLen = PCAP_NG_BLOCK_BODY_LEN_SECTION_HEADER
	case PCAP_NG_BLOCK_TYPE_SIMPLE_PACKET:
		blockBodyLen = blockTotalLen - 12
	case PCAP_NG_BLOCK_TYPE_PACKET:
		capturedLen := bo.Uint32(blockData[16:20])
		capturedLenFull := uint32(math.Ceil(float64(capturedLen)/4)) * 4
		blockBodyLen = blockTotalLen - 12 - capturedLenFull
	}

	blockBodyData := blockData[:blockBodyLen]

	optsLen := blockTotalLen - 12 - blockBodyLen
	if optsLen > 0 {
		opts, err := PcapNgParseOptions(bo, blockData[12 + blockBodyLen:12 + blockBodyLen + optsLen])
	}
*/

/*
	return nil
}
*/

/*
func readPcapngSectionHeader(r io.Reader) (header *PcapngSectionHeader, opts []PcapNgOption, err error) {
	buf, err := read(r, PCAP_NG_FILE_HEADER_LENGTH)
	if err != nil {
		return nil, nil, err
	}

	header, err = NewPcapngSectionHeader(buf)
	if err != nil {
		return nil, nil, err
	}

	//
	// Read options
	//
	optsLen := header.TotalLength() - 12
	if optsLen > 0 {
		buf, err := read(r, optsLen)
		if err != nil {
			if err == io.EOF {
				return nil, nil, io.ErrUnexpectedEOF
			}

			return nil, nil, err
		}

		opts, err = PcapNgParseOptions(header.ByteOrder, buf)
	}

	//
	buf, err = read(r, PCAP_NG_BLOCK_TOTAL_LENGTH_BYTES)
	if err != nil {
		return nil, nil, err
	}

	return
}

func readPcapPacketHeader(r io.Reader, bo binary.ByteOrder) (*PcapPacketHeader, error) {
	buf, err := read(r, PCAP_PACKET_HEADER_LENGTH)
	if err != nil {
		return nil, err
	}

	return NewPcapPacketHeader(buf, bo)
}
*/

/*
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

func read(r io.Reader, n uint32) (data []byte, err error) {
	buf := make([]byte, n)

	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

/*
func readExactly(r io.Reader, n uint32) (data []byte, err error) {
	buf, err := read(r, n)
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
}

func readdebug(a ...interface{}) {
	if true {
		debug("debug-read:", a...)
	}
}
*/
