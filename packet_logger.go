package main

import (
	"fmt"
	"io"
)

type LoggingPacketListener struct {
	writer io.Writer
}

func (l LoggingPacketListener) NewPacket(fileHeader PcapFileHeader, pcapPacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	if transportLayer != nil {
		switch transportLayer.(type) {
		case *TCPFrame:
			tcpFrame := *transportLayer.(*TCPFrame)

			io.WriteString(l.writer, fmt.Sprintf("[%-37s] %15s:%-5d -> %15s:%-5d: %s, TCP [%7s], SN: %d, AN: %d, payload len: %d\n",
				pcapPacketHeader.Timestamp(),
				sourceAddressToString(networkLayer), tcpFrame.Header.SourcePort(),
				destinationAddressToString(networkLayer), tcpFrame.Header.DestinationPort(),
				networkTypeString(networkLayer), flagString(*tcpFrame.Header),
				//from.RelativeSequenceNumber(tcpFrame.Header.SequenceNumber()), // FIXME
				//to.RelativeSequenceNumber(tcpFrame.Header.AcknowledgeNumber()), // FIXME
				tcpFrame.Header.SequenceNumber(),
				tcpFrame.Header.AcknowledgeNumber(),
				len(tcpFrame.Payload)))
		case *ICMPFrame:
			icmpFrame := *transportLayer.(*ICMPFrame)

			io.WriteString(l.writer, fmt.Sprintf("[%-37s] %15s -> %15s: ICMP Type %d\n",
				pcapPacketHeader.Timestamp(),
				sourceAddressToString(networkLayer),
				destinationAddressToString(networkLayer),
				icmpFrame.Header.Type()))
		case *UDPFrame:
			udpFrame := *transportLayer.(*UDPFrame)

			io.WriteString(l.writer, fmt.Sprintf("[%-37s] %15s:%-5d -> %15s:%-5d: %s, UDP, payload len: %d\n",
				pcapPacketHeader.Timestamp(),
				sourceAddressToString(networkLayer), udpFrame.Header.SourcePort(),
				destinationAddressToString(networkLayer), udpFrame.Header.DestinationPort(),
				networkTypeString(networkLayer),
				udpFrame.Header.Length()-UDP_FRAME_HEADER_LENGTH))
		}
	}
}

func networkTypeString(n interface{}) string {
	switch t := n.(type) {
	case *IPv4Frame:
		return "IPv4"
	case *IPv6Frame:
		return "IPv6"
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}
