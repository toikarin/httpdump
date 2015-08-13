package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

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
