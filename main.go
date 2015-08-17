package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
)

var wg sync.WaitGroup
var payloadMaxLength int = 1024 * 2
var logPackets = false
var logDebug = false

func main() {
	var flagPrintPackets bool
	var flagDebug bool
	var flagPayloadMaxLength int

	//
	// setup flags
	//
	flag.BoolVar(&flagPrintPackets, "print-packets", false, "log all packets")
	flag.BoolVar(&flagDebug, "debug", false, "print debug output")
	flag.IntVar(&flagPayloadMaxLength, "payload-len", 1024*2, "max length of the printed payload in bytes.")
	flag.Parse()

	//
	// handle flags
	//
	logPackets = flagPrintPackets
	logDebug = flagDebug
	payloadMaxLength = flagPayloadMaxLength

	mpl := MultiPacketListener{}
	if logPackets {
		mpl.Add(LoggingPacketListener{os.Stdout})
	}

	htl := NewHTTPTcpListener()
	tsl := TCPPacketListener{NewTCPStack(htl)}
	mpl.Add(&tsl)

	var r io.Reader

	if len(flag.Args()) != 0 {
		//
		// Read from file
		//
		var err error

		r, err = os.Open(flag.Arg(0))
		if err != nil {
			panic(err)
		}

	} else {
		//
		// Read from stdin
		//
		r = os.Stdin
	}

	err := readStream(r, mpl)
	if err != nil {
		if err == INVALID_FILETYPE {
			fmt.Println("error: not pcap file.")
		} else {
			fmt.Println("unknown error:", err)
		}
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
