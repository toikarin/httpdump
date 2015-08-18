package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

var payloadMaxLength int = 1024 * 2
var logPackets = false
var logDebug = false

func main() {
	var cmd *exec.Cmd

	var flagPrintPackets bool
	var flagDebug bool
	var flagPayloadMaxLength int
	var flagFile string
	var flagInterface string

	//
	// setup flags
	//
	flag.BoolVar(&flagPrintPackets, "print-packets", false, "")
	flag.BoolVar(&flagDebug, "debug", false, "")
	flag.IntVar(&flagPayloadMaxLength, "payload-len", 1024*2, "")
	flag.StringVar(&flagFile, "r", "", "")
	flag.StringVar(&flagInterface, "i", "", "")

	flag.Usage = func() {
		os.Stderr.WriteString(fmt.Sprintf("Usage: %s [expression]:\n", os.Args[0]))
		os.Stderr.WriteString("expression can be any expression that tcpdump supports.\n")
		os.Stderr.WriteString("\n")
		os.Stderr.WriteString("Options:\n")
		os.Stderr.WriteString("  -i <interface>. Listen on interface. Passed to tcpdump.\n")
		os.Stderr.WriteString("  -r <file>. Read packets from file.\n")
		os.Stderr.WriteString("  -payload-len <len>: Limit printed HTTP payload length to len bytes. [default 2048].\n")
		os.Stderr.WriteString("  -debug: Print debug output.\n")
		os.Stderr.WriteString("  -print-packets: Print all packets.\n\n")
		os.Stderr.WriteString("\n")
		os.Stderr.WriteString("Example:\n")
		os.Stderr.WriteString(fmt.Sprintf("%s -i eth0 host example.com and port 80\n", os.Args[0]))
		os.Stderr.WriteString("\n")
	}
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
	tcpStack := NewTCPStack(htl)
	tsl := TCPPacketListener{tcpStack}
	mpl.Add(&tsl)

	//
	// init debug monitor
	//
	var monitor *Monitor
	if logDebug {
		monitor = NewMonitor(tcpStack, htl)
		go monitor.RunPeriodic()
	}

	//
	// Determinate where to read from (stdin / file)
	//
	var r io.Reader

	switch flagFile {
	case "-":
		//
		// Read from stdin
		//
		r = os.Stdin
	case "":
		//
		// init tcpdump commad
		//
		var err error
		args := []string{"-U", "-w", "-"}
		if flagInterface != "" {
			args = append(args, "-i", flagInterface)
		}

		if len(flag.Args()) > 0 {
			args = append(args, strings.Join(flag.Args(), " "))
		}

		maindebug(fmt.Sprintf("Running cmd: 'tcpdump %s'", strings.Join(args, " ")))
		cmd = exec.Command("tcpdump", args...)

		r, err = cmd.StdoutPipe()
		if err != nil {
			// should not happend
			panic(err)
		}

		cmd.Stderr = os.Stderr

		//
		// start tcpdump
		//
		err = cmd.Start()
		if err != nil {
			fatal(err)
		}
	default:
		//
		// Read from file
		//
		var err error

		r, err = os.Open(flagFile)
		if err != nil {
			fatal(err)
		}
	}

	//
	// Run
	//
	err := readStream(r, mpl)
	if err != nil {
		if err == INVALID_FILETYPE {
			fmt.Println("error: not pcap file.")
		} else {
			fmt.Println("unknown error:", err)
		}
	}

	//
	// Close
	//
	if monitor != nil {
		monitor.Close()
	}

	for _, v := range htl.conns {
		v.Close()
	}

	if cmd != nil {
		err = cmd.Wait()
		if err != nil {
			//
			// exit with same exit code than tcpdump
			//
			if exiterr, ok := err.(*exec.ExitError); ok {
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					os.Exit(status.ExitStatus())
				}
			}

			panic(err)
		}
	}
}

func fatal(v ...interface{}) {
	os.Stderr.WriteString(fmt.Sprintln(v...))
	os.Exit(1)
}

func maindebug(a ...interface{}) {
	if true {
		debug("debug-main:", a...)
	}
}
