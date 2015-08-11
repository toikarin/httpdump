package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
)

var connmap map[FlowAddress]*Conn
var wg sync.WaitGroup
var payloadMaxLength = 1024 * 2

func main() {
	connmap = make(map[FlowAddress]*Conn)

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

	for _, v := range connmap {
		if v.HttpData != nil {
			v.HttpData.Close()
		}
	}

	wg.Wait()
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
	if false {
		fmt.Printf("%15s:%-5d -> %15s:%-5d: IPv%d, UDP, payload len: %d\n", sourceAddressToString(ipFrameHeader),
			udpFrameHeader.SourcePort(), destinationAddressToString(ipFrameHeader),
			udpFrameHeader.DestinationPort(), ipFrameHeader.Version(), payloadLen)
	}

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
	if false {
		fmt.Printf("%15s -> %15s: ICMP Type %d\n", sourceAddressToString(ipFrameHeader),
			destinationAddressToString(ipFrameHeader), icmpFrameHeader.Type())
	}

	return nil
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
	IpFrameHeader *NetworkLayerFrame
	Data          []byte
}

type TcpProtocol uint8

const (
	TCP_PROTO_INITIAL TcpProtocol = iota
	TCP_PROTO_HTTP
	TCP_PROTO_UNKNOWN = 255
)

type Conn struct {
	ClientFlow *Flow
	ServerFlow *Flow

	TcpProtocol TcpProtocol
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

func handleTCP(origPacketData []byte, ipFrameHeader NetworkLayerFrame) error {
	packetData := origPacketData
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

	var conn *Conn
	seq := tcpFrameHeader.SequenceNumber()

	clientFlowAddress := FlowAddress{sourceAddressToString(ipFrameHeader), tcpFrameHeader.SourcePort(), destinationAddressToString(ipFrameHeader), tcpFrameHeader.DestinationPort()}

	if tcpFrameHeader.FlagSYN() && !tcpFrameHeader.FlagACK() {

		//
		// create flows
		//
		clientFlow := &Flow{clientFlowAddress, 0, 0}
		clientFlow.SetInitialSequence(seq)

		serverFlowAddress := FlowAddress{destinationAddressToString(ipFrameHeader), tcpFrameHeader.DestinationPort(), sourceAddressToString(ipFrameHeader), tcpFrameHeader.SourcePort()}
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
	if tcpFrameHeader.FlagSYN() && tcpFrameHeader.FlagACK() {
		conn.ServerFlow.SetInitialSequence(seq)
	}

	//
	// check packet order
	//
	if seq > from.ExpectedSequenceNumber {
		// future packet
		conn.Buffer[seq] = &BufferedPacket{&ipFrameHeader, origPacketData}
		skip = true
		return nil
	} else if seq < from.ExpectedSequenceNumber {
		// past packet
		return nil
	}

	//
	// Read TCP payload
	//
	payloadLen := uint32(ipFrameHeader.TotalLength() - uint16(ipFrameHeader.HeaderLength()) - uint16(tcpFrameHeader.DataOffset()))

	if payloadLen > 0 && !skip {
		payload := packetData[:payloadLen]

		//
		// try to identify protocol
		//
		if conn.TcpProtocol == TCP_PROTO_INITIAL {
			if isHttpReq(payload) {
				conn.TcpProtocol = TCP_PROTO_HTTP
				conn.HttpData = newHttpData()
			} else {
				conn.TcpProtocol = TCP_PROTO_UNKNOWN
			}
		}

		//
		// handle HTTP
		//
		if conn.TcpProtocol == TCP_PROTO_HTTP {
			if isClient {
				conn.HttpData.ReqWriter.Write(payload)
			} else {
				conn.HttpData.RespWriter.Write(payload)
			}
		}

		//
		// increment next expected sequence number
		//
		from.ExpectedSequenceNumber += payloadLen
	} else {
		//
		// increment next expected sequence number
		//
		if tcpFrameHeader.FlagSYN() {
			from.ExpectedSequenceNumber += 1
		}
	}

	//
	// Handle FIN
	//
	if tcpFrameHeader.FlagFIN() {
		fmt.Println("FIXME: handle FIN")
		if conn.HttpData != nil {
			conn.HttpData.Close()
		}
	}

	//
	// Log packet
	//
	if true {
		fmt.Printf("%15s:%-5d -> %15s:%-5d: IPv%d, TCP [%7s], RSN: %d, RAN: %d, payload len: %d\n",
			sourceAddressToString(ipFrameHeader), tcpFrameHeader.SourcePort(),
			destinationAddressToString(ipFrameHeader), tcpFrameHeader.DestinationPort(),
			ipFrameHeader.Version(), flagString(*tcpFrameHeader),
			from.RelativeSequenceNumber(tcpFrameHeader.SequenceNumber()),
			to.RelativeSequenceNumber(tcpFrameHeader.AcknowledgeNumber()),
			payloadLen)
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
		handleTCP(bp.Data, *bp.IpFrameHeader) // FIXME: handle error
	}

	return nil
}

func printHttpRequest(httpData *HttpData) {
	for {
		//
		// Read request
		//
		req, err := http.ReadRequest(bufio.NewReader(httpData.ReqReader))
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				return
			}

			fmt.Println(err) // FIXME
			continue
		}

		//
		// Print Request-Line
		//
		fmt.Println(green(fmt.Sprintf("%s %s %s", req.Method, req.URL, req.Proto)))

		//
		// Print headers
		//
		for k, va := range req.Header {
			for _, v := range va {
				fmt.Println(green(fmt.Sprintf("%s: %s", k, v)))
			}
		}

		//
		// Print content
		//
		if req.ContentLength > 0 {
			//
			// Print only text content
			//
			if isTextContentType(req.Header.Get("Content-Type")) {
				defer req.Body.Close()
				buf, err := ioutil.ReadAll(req.Body)
				if err != nil {
					// FIXME
				}

				fmt.Println()
				fmt.Println(green(string(buf)))
			} else {
				fmt.Println()
				fmt.Println(green("<binary content>"))
			}
		}
	}
}

func statusText(statusStr string) string {
	splitted := strings.Split(statusStr, " ")
	statusCode, _ := strconv.Atoi(splitted[0])
	statusMessage := splitted[1]
	var statusCodeStr string

	switch {
	case 200 <= statusCode && statusCode <= 299:
		statusCodeStr = green(strconv.Itoa(statusCode))
	case 300 <= statusCode && statusCode <= 399:
		statusCodeStr = green(strconv.Itoa(statusCode))
	case 400 <= statusCode && statusCode <= 499:
		statusCodeStr = green(strconv.Itoa(statusCode))
	case 500 <= statusCode && statusCode <= 599:
		statusCodeStr = green(strconv.Itoa(statusCode))
	default:
		statusCodeStr = green(strconv.Itoa(statusCode))
	}

	return statusCodeStr + " " + statusMessage
}

func printHttpResponse(httpData *HttpData) {
	for {
		resp, err := http.ReadResponse(bufio.NewReader(httpData.RespReader), nil)
		if err != nil {
			if err == io.ErrClosedPipe || err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			fmt.Println("ERROR WHILE READING RESPONSE")
			fmt.Println(err)

			continue
		}

		//
		// Print Response-line
		//
		fmt.Println(yellow(fmt.Sprintf("%s %s", resp.Proto, statusText(resp.Status))))

		//
		// Print headers
		//
		for k, va := range resp.Header {
			for _, v := range va {
				fmt.Println(yellow(fmt.Sprintf("%s: %s", k, v)))
			}
		}

		//
		// Print content
		//
		if resp.ContentLength > 0 {
			//
			// Read full response
			//
			defer resp.Body.Close()
			buf, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				// FIXME
			}

			if isTextContentType(resp.Header.Get("Content-Type")) {
				switch resp.Header.Get("Content-Encoding") {
				case "":
					// do nothing
				case "gzip":
					buf, err = readGzip(buf)
					// FIXME: handle err
				default:
					// unknown encoding
					buf = nil
				}

				printPayload(buf, buf != nil)
			} else {
				printPayload(nil, false)
			}
		}
	}
}

func readGzip(data []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	defer gzipReader.Close()

	buf, err := ioutil.ReadAll(gzipReader)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func printPayload(buf []byte, isText bool) {
	if isText {
		printTextPayload(buf)
	} else {
		fmt.Println()
		fmt.Println(blue("<binary content>"))
	}
}

func printTextPayload(buf []byte) {
	payloadStr := string(buf)
	payloadLen := len(payloadStr)
	snipped := 0

	//
	// check if payload needs to be cut
	//
	if payloadLen > payloadMaxLength {
		payloadStr = payloadStr[:payloadMaxLength]
		snipped = payloadLen - payloadMaxLength
	}

	//
	// print
	//
	fmt.Println()
	fmt.Print(blue(payloadStr))
	if snipped > 0 {
		fmt.Printf("... (%d bytes snipped)", snipped)
	}
	fmt.Println()
}

func isTextContentType(ct string) bool {
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/x-javascript")
}

func isHttpReq(bytes []byte) bool {
	l := len(bytes)

	for i, b := range bytes {
		//
		// minimum number of bytes before ' HTTP...'
		//
		if i < 3 {
			continue
		}

		if i+11 > l {
			return false
		}

		// find request-line ending, example: ' HTTP/1.1<CR><LF>'
		if b == ' ' &&
			bytes[i+1] == 'H' &&
			bytes[i+2] == 'T' &&
			bytes[i+3] == 'T' &&
			bytes[i+4] == 'P' &&
			bytes[i+5] == '/' &&
			'0' <= bytes[i+6] && bytes[i+6] <= '9' &&
			bytes[i+7] == '.' &&
			'0' <= bytes[i+8] && bytes[i+8] <= '9' &&
			bytes[i+9] == 13 && // CR
			bytes[i+10] == 10 { // LF
			return true
		}

		// check byte is TEXT
		if b <= 31 && b >= 127 {
			return false
		}
	}

	return false
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

func sourceAddress(a interface{}) interface{} {
	switch t := a.(type) {
	case *IPv4FrameHeader:
		return a.(*IPv4FrameHeader).SourceAddress()
	case *IPv6FrameHeader:
		return a.(*IPv6FrameHeader).SourceAddress()
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func destinationAddress(a interface{}) interface{} {
	switch t := a.(type) {
	case *IPv4FrameHeader:
		return a.(*IPv4FrameHeader).DestinationAddress()
	case *IPv6FrameHeader:
		return a.(*IPv6FrameHeader).DestinationAddress()
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
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
