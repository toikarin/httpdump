package main

import (
	"fmt"
	"io"
	"os"
	"sync"
)

var connmap map[FlowAddress]*Conn
var wg sync.WaitGroup
var payloadMaxLength = 1024 * 2
var logPackets = true

func main() {
	connmap = make(map[FlowAddress]*Conn)

	if len(os.Args) > 1 {
		// Read from file
		f, err := os.Open(os.Args[1])
		if err != nil {
			panic(err)
		}

		readStream(f, MyPacketListener{})
	} else {
		// Read from stdin
		readStream(os.Stdin, MyPacketListener{})
	}

	for _, v := range connmap {
		if v.HttpData != nil {
			v.HttpData.Close()
		}
	}

	wg.Wait()
}

type MyPacketListener struct {
}

func (MyPacketListener) NewPacket(fileHeader PcapFileHeader, ipacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	if transportLayer != nil {
		switch transportLayer.(type) {
		case *TCPFrame:
			if logPackets {
				handleTCP(networkLayer, *transportLayer.(*TCPFrame))
			}
		case *ICMPFrame:
			if logPackets {
				handleICMP(networkLayer, *transportLayer.(*ICMPFrame))
			}
		case *UDPFrame:
			if logPackets {
				handleUDP(networkLayer, *transportLayer.(*UDPFrame))
			}
		}
	}
}

func handleUDP(networkFrame interface{}, udpFrame UDPFrame) {
	fmt.Printf("%15s:%-5d -> %15s:%-5d: %s, UDP, payload len: %d\n",
		sourceAddressToString(networkFrame), udpFrame.Header.SourcePort(),
		destinationAddressToString(networkFrame), udpFrame.Header.DestinationPort(),
		networkTypeString(networkFrame),
		udpFrame.Header.Length()-UDP_FRAME_HEADER_LENGTH)
}

func handleICMP(networkFrame interface{}, icmpFrame ICMPFrame) {
	fmt.Printf("%15s -> %15s: ICMP Type %d\n", sourceAddressToString(networkFrame),
		destinationAddressToString(networkFrame), icmpFrame.Header.Type())
}

type HttpData struct {
	Http       bool
	ReqReader  *io.PipeReader
	ReqWriter  *io.PipeWriter
	RespReader *io.PipeReader
	RespWriter *io.PipeWriter
}

func (httpData *HttpData) Close() {
	if httpData.ReqWriter != nil {
		httpData.ReqWriter.Close()
	}
	if httpData.RespWriter != nil {
		httpData.RespWriter.Close()
	}
}

type BufferedPacket struct {
	NetworkFrame *interface{}
	TCPFrame     TCPFrame
}

type TCPProtocol uint8

const (
	TCP_PROTO_INITIAL TCPProtocol = iota
	TCP_PROTO_HTTP
	TCP_PROTO_UNKNOWN = 255
)

type Conn struct {
	ClientFlow *Flow
	ServerFlow *Flow

	TCPProtocol TCPProtocol
	Buffer      map[uint32]*BufferedPacket

	HttpData *HttpData
}

type Flow struct {
	Address                FlowAddress
	InitialSequenceNumber  uint32
	ExpectedSequenceNumber uint32
}

func (f *Flow) SetInitialSequence(s uint32) {
	f.InitialSequenceNumber = s
	f.ExpectedSequenceNumber = s
}

func (f *Flow) RelativeSequenceNumber(s uint32) uint32 {
	if s == 0 {
		return 0
	}

	return s - f.InitialSequenceNumber + 1
}

type FlowAddress struct {
	ClientAddress string
	ClientPort    uint16

	ServerAddress string
	ServerPort    uint16
}

func newHttpData() *HttpData {
	//
	// Create HttpData
	//
	httpData := &HttpData{}
	httpData.ReqReader, httpData.ReqWriter = io.Pipe()
	httpData.RespReader, httpData.RespWriter = io.Pipe()
	wg.Add(2)

	go func(httpData *HttpData) {
		defer wg.Done()
		printHttpRequest(httpData)
	}(httpData)

	go func(httpData *HttpData) {
		defer wg.Done()
		printHttpResponse(httpData)
	}(httpData)

	return httpData
}

func handleTCP(networkFrame interface{}, tcpFrame TCPFrame) error {
	var conn *Conn
	seq := tcpFrame.Header.SequenceNumber()
	clientFlowAddress := FlowAddress{sourceAddressToString(networkFrame), tcpFrame.Header.SourcePort(), destinationAddressToString(networkFrame), tcpFrame.Header.DestinationPort()}

	if tcpFrame.Header.FlagSYN() && !tcpFrame.Header.FlagACK() {
		//
		// create flows
		//
		clientFlow := &Flow{clientFlowAddress, 0, 0}
		clientFlow.SetInitialSequence(seq)

		serverFlowAddress := FlowAddress{destinationAddressToString(networkFrame), tcpFrame.Header.DestinationPort(), sourceAddressToString(networkFrame), tcpFrame.Header.SourcePort()}
		serverFlow := &Flow{serverFlowAddress, 0, 0}

		// create conns
		conn = &Conn{clientFlow, serverFlow, TCP_PROTO_INITIAL, make(map[uint32]*BufferedPacket), nil}
		connmap[clientFlowAddress] = conn
		connmap[serverFlowAddress] = conn
	}

	var ok bool
	conn, ok = connmap[clientFlowAddress]
	if !ok {
		//fmt.Println("Unknown connection")
		return nil
	}

	//
	// Determinate client and server flows
	//
	var from, to *Flow
	var isClient bool

	if conn.ClientFlow.Address == clientFlowAddress {
		from, to = conn.ClientFlow, conn.ServerFlow
		isClient = true
	} else {
		from, to = conn.ServerFlow, conn.ClientFlow
		isClient = false
	}

	skip := false

	// handle SYN+ACK
	if tcpFrame.Header.FlagSYN() && tcpFrame.Header.FlagACK() {
		conn.ServerFlow.SetInitialSequence(seq)
	}

	//
	// check packet order
	//
	if seq > from.ExpectedSequenceNumber {
		// future packet
		conn.Buffer[seq] = &BufferedPacket{&networkFrame, tcpFrame}
		skip = true
		return nil
	} else if seq < from.ExpectedSequenceNumber {
		// past packet
		return nil
	}

	//
	// Read TCP payload
	//

	if len(tcpFrame.Payload) > 0 && !skip {
		//
		// try to identify protocol
		//
		if conn.TCPProtocol == TCP_PROTO_INITIAL {
			if isHttpReq(tcpFrame.Payload) {
				conn.TCPProtocol = TCP_PROTO_HTTP
				conn.HttpData = newHttpData()
			} else {
				conn.TCPProtocol = TCP_PROTO_UNKNOWN
			}
		}

		//
		// handle HTTP
		//
		if conn.TCPProtocol == TCP_PROTO_HTTP {
			if isClient {
				conn.HttpData.ReqWriter.Write(tcpFrame.Payload)
			} else {
				conn.HttpData.RespWriter.Write(tcpFrame.Payload)
			}
		}

		//
		// increment next expected sequence number
		//
		from.ExpectedSequenceNumber += uint32(len(tcpFrame.Payload))
	} else {
		//
		// increment next expected sequence number
		//
		if tcpFrame.Header.FlagSYN() {
			from.ExpectedSequenceNumber += 1
		}
	}

	//
	// Handle FIN
	//
	if tcpFrame.Header.FlagFIN() {
		fmt.Println("FIXME: handle FIN")
		if conn.HttpData != nil {
			conn.HttpData.Close()
		}
	}

	//
	// Log packet
	//
	if logPackets {
		fmt.Printf("%15s:%-5d -> %15s:%-5d: %s, TCP [%7s], RSN: %d, RAN: %d, payload len: %d\n",
			sourceAddressToString(networkFrame), tcpFrame.Header.SourcePort(),
			destinationAddressToString(networkFrame), tcpFrame.Header.DestinationPort(),
			networkTypeString(networkFrame), flagString(*tcpFrame.Header),
			from.RelativeSequenceNumber(tcpFrame.Header.SequenceNumber()),
			to.RelativeSequenceNumber(tcpFrame.Header.AcknowledgeNumber()),
			len(tcpFrame.Payload))
	}

	//
	// handle buffered packets
	//
	for {
		bp, ok := conn.Buffer[from.ExpectedSequenceNumber]
		if !ok {
			break
		}

		delete(conn.Buffer, from.ExpectedSequenceNumber)
		handleTCP(*bp.NetworkFrame, bp.TCPFrame) // FIXME: handle error
	}

	return nil
}

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
