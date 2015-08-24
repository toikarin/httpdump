package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go-libpcap"
	"go-libpcapng"
	"io"
	"time"
)

type PacketListener interface {
	NewPacket(timestamp time.Time, linkLayer, networkLayer, transportLayer interface{})
}

func readStream(r io.Reader, packetListener PacketListener) error {
	data, err := readExactly(r, 4)
	if err != nil {
		return err
	}

	// put data back to reader
	r = io.MultiReader(bytes.NewReader(data), r)

	if pcapng.IsPcapngStream(data) {
		readdebug("pcapng format detected")

		stream := pcapng.NewStream(r)

		for {
			block, err := stream.NextBlock()
			if err != nil {
				return err
			}

			switch block.(type) {
			case *pcapng.EnhancedPacketBlock:
				epb := block.(*pcapng.EnhancedPacketBlock)

				linkLayer, networkLayer, transportLayer, err := readLayerPacket(uint32(epb.Interface.LinkType), stream.ByteOrder(), epb.PacketData)
				if err != nil {
					return err
				}

				packetListener.NewPacket(epb.Timestamp, linkLayer, networkLayer, transportLayer)
			}
		}
	} else if pcap.IsPcapStream(data) {
		readdebug("pcap format detected")

		stream, fileHeader, err := pcap.NewStream(r)
		if err != nil {
			return err
		}

		for {
			packetHeader, data, err := stream.NextPacket()
			if err != nil {
				return err
			}

			linkLayer, networkLayer, transportLayer, err := readLayerPacket(fileHeader.Network(), fileHeader.ByteOrder, data)
			if err != nil {
				return err
			}

			packetListener.NewPacket(packetHeader.Timestamp(), linkLayer, networkLayer, transportLayer)
		}
	}

	return nil
}

func readLayerPacket(network uint32, byteOrder binary.ByteOrder, packetData []byte) (linkLayer, networkLayer, transportLayer interface{}, err error) {
	var protocol uint8
	var payload []byte
	var linkFrame interface{}
	var networkFrame interface{}
	var etherType uint16

	//
	// Read layer frame
	//
	switch network {
	case pcap.LINKTYPE_ETHERNET:
		ethernetFrame, err := NewEthernetFrame(packetData)
		if err != nil {
			return nil, nil, nil, err
		}
		if ethernetFrame == nil {
			return nil, nil, nil, nil
		}

		etherType = ethernetFrame.Header.Type()
		payload = ethernetFrame.Payload
	case pcap.LINKTYPE_NULL:
		nullFrame, err := NewNullFrame(packetData, byteOrder)
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

func read(r io.Reader, n uint32) (data []byte, err error) {
	buf := make([]byte, n)

	if _, err = io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func readExactly(r io.Reader, n uint32) (data []byte, err error) {
	buf, err := read(r, n)
	if err == io.EOF {
		return nil, io.ErrUnexpectedEOF
	}

	return buf, err
}

func readdebug(a ...interface{}) {
	if true {
		debug("debug-read:", a...)
	}
}
