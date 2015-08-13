package main

import (
	"fmt"
	"os"
	"sync"
)

var wg sync.WaitGroup
var payloadMaxLength = 1024 * 2
var logPackets = false

func main() {
	mpl := MultiPacketListener{}
	if (logPackets) {
		mpl.Add(LoggingPacketListener{})
	}

	htl := NewHTTPTcpListener()
	tsl := TCPPacketListener{NewTCPStack(htl)}
	mpl.Add(&tsl)

	if len(os.Args) > 1 {
		// Read from file
		f, err := os.Open(os.Args[1])
		if err != nil {
			panic(err)
		}

		readStream(f, mpl)
	} else {
		// Read from stdin
		readStream(os.Stdin, mpl)
	}

	/*
	for _, v := range connmap {
		/*
		if v.HttpData != nil {
			v.HttpData.Close()
		}
	}
	*/

	wg.Wait()
}

type MultiPacketListener struct {
	PacketListeners []PacketListener
}

func (mpl *MultiPacketListener) Add(pl PacketListener) {
	mpl.PacketListeners = append(mpl.PacketListeners, pl)
}

func (mpl MultiPacketListener) NewPacket(pcapFileHeader PcapFileHeader, pcapPacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	for _, pk := range mpl.PacketListeners {
		pk.NewPacket(pcapFileHeader, pcapPacketHeader, linkLayer, networkLayer, transportLayer)
	}
}

type LoggingPacketListener struct {}

func (LoggingPacketListener) NewPacket(fileHeader PcapFileHeader, pcapPacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	if transportLayer != nil {
		switch transportLayer.(type) {
		case *TCPFrame:
			tcpFrame := *transportLayer.(*TCPFrame)

			//fmt.Printf("%15s:%-5d -> %15s:%-5d: %s, TCP [%7s], RSN: %d, RAN: %d, payload len: %d\n", // FIXME
			fmt.Printf("%15s:%-5d -> %15s:%-5d: %s, TCP [%7s], SN: %d, AN: %d, payload len: %d\n",
				sourceAddressToString(networkLayer), tcpFrame.Header.SourcePort(),
				destinationAddressToString(networkLayer), tcpFrame.Header.DestinationPort(),
				networkTypeString(networkLayer), flagString(*tcpFrame.Header),
				//from.RelativeSequenceNumber(tcpFrame.Header.SequenceNumber()), // FIXME
				//to.RelativeSequenceNumber(tcpFrame.Header.AcknowledgeNumber()), // FIXME
				tcpFrame.Header.SequenceNumber(),
				tcpFrame.Header.AcknowledgeNumber(),
				len(tcpFrame.Payload))
		case *ICMPFrame:
			icmpFrame := *transportLayer.(*ICMPFrame)

			fmt.Printf("%15s -> %15s: ICMP Type %d\n", sourceAddressToString(networkLayer),
				destinationAddressToString(networkLayer), icmpFrame.Header.Type())
		case *UDPFrame:
			udpFrame := *transportLayer.(*UDPFrame)

			fmt.Printf("%15s:%-5d -> %15s:%-5d: %s, UDP, payload len: %d\n",
				sourceAddressToString(networkLayer), udpFrame.Header.SourcePort(),
				destinationAddressToString(networkLayer), udpFrame.Header.DestinationPort(),
				networkTypeString(networkLayer),
				udpFrame.Header.Length()-UDP_FRAME_HEADER_LENGTH)
		}
	}
}

type TCPPacketListener struct {
	tcpStack *TCPStack
}

func (l *TCPPacketListener) NewPacket(fileHeader PcapFileHeader, pcapPacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	if transportLayer != nil {
		switch transportLayer.(type) {
		case *TCPFrame:
			tcpFrame := transportLayer.(*TCPFrame)
			nl := networkLayer
			l.tcpStack.NewPacket(&nl, tcpFrame)
		}
	}
}

type TCPProtocol uint8

const (
	TCP_PROTO_INITIAL TCPProtocol = iota
	TCP_PROTO_HTTP
	TCP_PROTO_UNKNOWN = 255
)

func red(s string) string {
	return "\033[31m" + s + "\033[0m"
}

func yellow(s string) string {
	return "\033[34m" + s + "\033[0m"
}

func blue(s string) string {
	return "\033[94m" + s + "\033[0m"
}

func green(s string) string {
	return "\033[92m" + s + "\033[0m"
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

func sourceAddress(a interface{}) interface{} {
	switch t := a.(type) {
	case *IPv4Frame:
		return a.(*IPv4Frame).Header.SourceAddress()
	case *IPv6Frame:
		return a.(*IPv6Frame).Header.SourceAddress()
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func destinationAddress(a interface{}) interface{} {
	switch t := a.(type) {
	case *IPv4Frame:
		return a.(*IPv4Frame).Header.DestinationAddress()
	case *IPv6Frame:
		return a.(*IPv6Frame).Header.DestinationAddress()
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func sourceAddressToString(a interface{}) string {
	switch t := a.(type) {
	case *IPv4Frame:
		return IPv4String(a.(*IPv4Frame).Header.SourceAddress())
	case IPv4Frame:
		return IPv4String(a.(IPv4Frame).Header.SourceAddress())
	case *IPv6Frame:
		return IPv6String(a.(*IPv6Frame).Header.SourceAddress())
	case IPv6Frame:
		return IPv6String(a.(IPv6Frame).Header.SourceAddress())
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func destinationAddressToString(a interface{}) string {
	switch t := a.(type) {
	case *IPv4Frame:
		return IPv4String(a.(*IPv4Frame).Header.DestinationAddress())
	case *IPv6Frame:
		return IPv6String(a.(*IPv6Frame).Header.DestinationAddress())
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}
