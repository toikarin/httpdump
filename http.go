package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type HttpData struct {
	conn         TCPListenerConnection
	dataReceived bool

	reqReader  *io.PipeReader
	reqWriter  *io.PipeWriter
	respReader *io.PipeReader
	respWriter *io.PipeWriter

	reqRespWriter *HttpRequestResponseWriter
}

func (httpData *HttpData) Close() {
	if httpData.reqWriter != nil {
		httpData.reqWriter.Close()
	}
	if httpData.respWriter != nil {
		httpData.respWriter.Close()
	}
	if httpData.reqRespWriter != nil {
		httpData.reqRespWriter.Close()
	}
}

type HttpTCPListener struct {
	conns map[TCPListenerConnection]*HttpData
}

func NewHTTPTcpListener() *HttpTCPListener {
	h := HttpTCPListener{}
	h.conns = make(map[TCPListenerConnection]*HttpData)

	return &h
}

func (htl *HttpTCPListener) NewConnection(conn TCPListenerConnection) {
	httpData := &HttpData{}
	httpData.conn = conn
	htl.conns[conn] = httpData

	httpdebug("new connection")
}

func (htl *HttpTCPListener) Data(conn TCPListenerConnection, data []byte, isClient bool) {
	httpdebug("data")
	//
	// find connection
	//
	httpData, ok := htl.conns[conn]

	// if connection is not found, ignore the data
	if !ok {
		httpdebug("data ignored")
		return
	}

	//
	// is this initial data package for this connection?
	//
	if !httpData.dataReceived {
		//
		// make sure the data is http
		//
		if !isHttpReq(data) {
			//
			// if data is not http, we are not interested in this connection
			//
			httpdebug("not http data")
			htl.ClosedConnection(conn)
			return
		}

		//
		// start request and response listeners
		//
		httpData.reqReader, httpData.reqWriter = io.Pipe()
		httpData.respReader, httpData.respWriter = io.Pipe()
		httpData.reqRespWriter = NewHttpRequestResponseWriter(os.Stdout, true)
		wg.Add(2)

		//
		// start goroutines
		//
		go httpData.reqRespWriter.Run()
		go func() {
			defer wg.Done()
			parseHttpRequest(httpData, httpData.reqRespWriter.ReqChan, true)
		}()
		go func() {
			defer wg.Done()
			parseHttpResponse(httpData, httpData.reqRespWriter.RespChan, false)
		}()

		httpData.dataReceived = true
	}
	httpdebug("data received")

	//
	// write data
	//
	if isClient {
		httpData.reqWriter.Write(data)
	} else {
		httpData.respWriter.Write(data)
	}
}

func (htl *HttpTCPListener) ClosedConnection(conn TCPListenerConnection) {
	httpData, ok := htl.conns[conn]
	if !ok {
		return
	}

	delete(htl.conns, conn)

	httpData.Close()
	httpdebug("closed")
}

func parseHttpResponse(httpData *HttpData, c chan []byte, addHeader bool) {
	for {
		var out bytes.Buffer

		resp, err := http.ReadResponse(bufio.NewReader(httpData.respReader), nil)
		if err != nil {
			if err == io.ErrClosedPipe || err == io.EOF || err == io.ErrUnexpectedEOF {
				return
			}
			fmt.Println("ERROR WHILE READING RESPONSE")
			fmt.Println(err)

			continue
		}

		//
		// Write header
		//
		if addHeader {
			writeHeader(&out, httpData)
		}

		//
		// Write Response-line
		//
		out.WriteString(yellow(fmt.Sprintf("%s %s", resp.Proto, statusText(resp.StatusCode, resp.Status))))
		out.WriteByte('\n')

		//
		// Write headers
		//
		for k, va := range resp.Header {
			for _, v := range va {
				out.WriteString(yellow(fmt.Sprintf("%s: %s", k, v)))
				out.WriteByte('\n')
			}
		}

		//
		// Write content
		//
		defer resp.Body.Close()
		buf, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			// FIXME
			continue
		}

		handlePayload(&out, buf, resp.Header)
		out.WriteByte('\n')
		c <- out.Bytes()
	}
}

func handlePayload(out *bytes.Buffer, buf []byte, headers http.Header) error {
	if len(buf) == 0 {
		return nil
	}

	contentType := headers.Get("Content-Type")
	if isTextContentType(contentType) {
		//
		// Handle Content-Encoding
		//
		ce := headers.Get("Content-Encoding")

		switch ce {
		case "":
			// do nothing
		case "gzip":
			var err error
			buf, err = readGzip(buf)
			if err != nil {
				return err
			}
		default:
			// unknown encoding
			httpdebug(fmt.Sprintf("Unknown Content-Encoding '%s'", ce))
			buf = nil
		}

		//
		// Write text payload
		//
		if buf != nil {
			writeTextPayload(out, buf)
		}
	} else {
		if isFullyPrintable(buf) {
			//
			// Write text payload
			//
			writeTextPayload(out, buf)
		} else {
			//
			// Write binary payload
			//
			out.WriteByte('\n')

			if contentType == "" {
				out.WriteString(blue("<binary content>"))
			} else {
				out.WriteString(blue(fmt.Sprintf("<binary content of type %s>", contentType)))
			}
		}
	}

	return nil
}

func parseHttpRequest(httpData *HttpData, c chan []byte, addHeader bool) {
	for {
		var out bytes.Buffer

		//
		// Read request
		//
		req, err := http.ReadRequest(bufio.NewReader(httpData.reqReader))
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				return
			}

			fmt.Println(err) // FIXME
			continue
		}

		//
		// Write header
		//
		if addHeader {
			writeHeader(&out, httpData)
		}

		//
		// Write Request-Line
		//
		out.WriteString(green(fmt.Sprintf("%s %s %s", req.Method, req.URL, req.Proto)))
		out.WriteByte('\n')

		//
		// Write headers
		//
		for k, va := range req.Header {
			for _, v := range va {
				out.WriteString(green(fmt.Sprintf("%s: %s", k, v)))
				out.WriteByte('\n')
			}
		}

		//
		// Write content
		//
		defer req.Body.Close()
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			// FIXME
			continue
		}

		handlePayload(&out, buf, req.Header)
		c <- out.Bytes()
	}
}

type HttpRequestResponseWriter struct {
	writer io.Writer
	mutual bool

	ReqChan  chan []byte
	RespChan chan []byte
	done     chan bool
}

func NewHttpRequestResponseWriter(writer io.Writer, mutual bool) *HttpRequestResponseWriter {
	return &HttpRequestResponseWriter{
		writer:   writer,
		mutual:   mutual,
		ReqChan:  make(chan []byte),
		RespChan: make(chan []byte),
		done:     make(chan bool),
	}
}

func (p *HttpRequestResponseWriter) Close() {
	close(p.ReqChan)
	close(p.RespChan)
	<-p.done
	close(p.done)
}

func (p *HttpRequestResponseWriter) Run() {
	for {
		//
		// Wait for request
		//
		req, ok := <-p.ReqChan

		if !ok {
			break
		}

		//
		// Write request without waiting for response if mutual flag is not set
		//
		if !p.mutual {
			p.writer.Write(req)
		}

		//
		// Wait for response
		//
		resp, ok := <-p.RespChan

		if !ok {
			//
			// Write already read request
			//
			if p.mutual {
				p.writer.Write(req)
			}

			break
		}

		//
		// Write either request+response or only response depending on the mutuality flag
		//
		if p.mutual {
			p.writer.Write(req)
		}
		p.writer.Write(resp)
	}

	p.done <- true
}

//
// helpers
//

func statusText(statusCode int, status string) string {
	splitted := strings.SplitN(status, " ", 2)
	statusMessage := splitted[1]

	var statusCodeStr string

	switch {
	case 200 <= statusCode && statusCode <= 299:
		statusCodeStr = green(strconv.Itoa(statusCode))
	case 300 <= statusCode && statusCode <= 399:
		statusCodeStr = yellow(strconv.Itoa(statusCode))
	case 400 <= statusCode && statusCode <= 499:
		statusCodeStr = yellow(strconv.Itoa(statusCode))
	case 500 <= statusCode && statusCode <= 599:
		statusCodeStr = red(strconv.Itoa(statusCode))
	default:
		statusCodeStr = red(strconv.Itoa(statusCode))
	}

	return statusCodeStr + " " + statusMessage
}

func readGzip(data []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	defer gzipReader.Close()

	return ioutil.ReadAll(gzipReader)
}

func writeHeader(out *bytes.Buffer, httpData *HttpData) {
	out.WriteString(fmt.Sprintf("[%s] %s -> %s:%d, req #%d",
		"17.08.2015 11:59:10",
		AddressToString(httpData.conn.ClientAddress),
		AddressToString(httpData.conn.ServerAddress),
		httpData.conn.ServerPort,
		1,
	))
	out.WriteByte('\n')
}

func writeTextPayload(out *bytes.Buffer, buf []byte) {
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
	// Write output
	//
	out.WriteByte('\n')
	out.WriteString(blue(payloadStr))
	if snipped > 0 {
		out.WriteString(fmt.Sprintf("... (%d bytes snipped)", snipped))
	}
}

func convertToPrintable(buf []byte) []byte {
	converted := make([]byte, len(buf))
	copy(converted, buf)

	for i, b := range converted {
		if b < 32 || b > 126 {
			converted[i] = '.'
		}
	}

	return converted
}

func isFullyPrintable(buf []byte) bool {
	for _, b := range buf {
		if b < 32 || b > 126 {
			return false
		}
	}

	return true
}

func isTextContentType(ct string) bool {
	return strings.HasPrefix(ct, "text/") ||
		strings.HasPrefix(ct, "application/json") ||
		strings.HasPrefix(ct, "application/x-javascript")
}

func isHttpReq(bytes []byte) bool {
	l := len(bytes)
	spacesFound := 0

	for i, b := range bytes {
		//
		// minimum number of bytes before ' HTTP...'
		//
		if i < 3 {
			continue
		}

		//
		// need at least 11 extra bytes
		//
		if i+11 > l {
			return false
		}

		if b == ' ' {
			spacesFound += 1

			// find request-line ending, example: ' HTTP/1.1<CR><LF>'
			if spacesFound >= 2 &&
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
		}

		//
		// check byte is still TEXT
		//
		if b <= 31 && b >= 127 {
			return false
		}
	}

	panic("should not end up here")
}

func httpdebug(a ...interface{}) {
	if true {
		debug("debug-http:", a...)
	}
}
