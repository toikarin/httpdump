package main

import (
	"testing"
)

type TestTcpFrameHeaderResult struct {
	SourcePort        uint16
	DestinationPort   uint16
	SequenceNumber    uint32
	AcknowledgeNumber uint32
	DataOffset        uint8
	Flags             uint16
	FlagNS            bool
	FlagCWR           bool
	FlagECE           bool
	FlagURG           bool
	FlagACK           bool
	FlagPSH           bool
	FlagRST           bool
	FlagSYN           bool
	FlagFIN           bool
	WindowSize        uint16
	Checksum          uint16
	UrgentPointer     uint16
}

func TestTcpParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestTcpFrameHeaderResult
	}{
		{[]byte{
			0x30, 0x39, // Source Port
			0x00, 0x50, // Destination Port
			0x01, 0x02, 0x03, 0x04, // Sequence Number
			0x04, 0x03, 0x02, 0x01, // Acknowledge Number
			0xa0, 0x18, // Data Offset + Flags
			0x39, 0x08, // Window Size
			0x96, 0x4e, // Checksum
			0x00, 0x00, // UrgentPointer
		}, TestTcpFrameHeaderResult{
			SourcePort:        12345,
			DestinationPort:   80,
			SequenceNumber:    16909060,
			AcknowledgeNumber: 67305985,
			DataOffset:        40,
			Flags:             24,
			FlagNS:            false,
			FlagCWR:           false,
			FlagECE:           false,
			FlagURG:           false,
			FlagACK:           true,
			FlagPSH:           true,
			FlagRST:           false,
			FlagSYN:           false,
			FlagFIN:           false,
			WindowSize:        14600,
			Checksum:          38478,
			UrgentPointer:     0,
		}},
	}

	for i, c := range cases {
		got, err := NewTcpFrameHeader(c.in)
		if err != nil {
			t.Fatal(err)
		}

		if got.SourcePort() != c.want.SourcePort {
			t.Errorf("NewTcpFrameHeaderTest[%d].SourcePort() mismatch, got: %d, want %d", i, got.SourcePort(), c.want.SourcePort)
		}

		if got.DestinationPort() != c.want.DestinationPort {
			t.Errorf("NewTcpFrameHeaderTest[%d].DestinationPort() mismatch, got: %d, want %d", i, got.DestinationPort(), c.want.DestinationPort)
		}

		if got.SequenceNumber() != c.want.SequenceNumber {
			t.Errorf("NewTcpFrameHeaderTest[%d].SequenceNumber() mismatch, got: %d, want %d", i, got.SequenceNumber(), c.want.SequenceNumber)
		}

		if got.AcknowledgeNumber() != c.want.AcknowledgeNumber {
			t.Errorf("NewTcpFrameHeaderTest[%d].AcknowledgeNumber() mismatch, got: %d, want %d", i, got.AcknowledgeNumber(), c.want.AcknowledgeNumber)
		}

		if got.DataOffset() != c.want.DataOffset {
			t.Errorf("NewTcpFrameHeaderTest[%d].DataOffset() mismatch, got: %d, want %d", i, got.DataOffset(), c.want.DataOffset)
		}

		if got.Flags() != c.want.Flags {
			t.Errorf("NewTcpFrameHeaderTest[%d].Flags() mismatch, got: %d, want %d", i, got.Flags(), c.want.Flags)
		}

		if got.FlagNS() != c.want.FlagNS {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagNS() mismatch, got: %t, want %t", i, got.FlagNS(), c.want.FlagNS)
		}

		if got.FlagCWR() != c.want.FlagCWR {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagCWR() mismatch, got: %t, want %t", i, got.FlagCWR(), c.want.FlagCWR)
		}

		if got.FlagECE() != c.want.FlagECE {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagECE() mismatch, got: %t, want %t", i, got.FlagECE(), c.want.FlagECE)
		}

		if got.FlagURG() != c.want.FlagURG {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagURG() mismatch, got: %t, want %t", i, got.FlagURG(), c.want.FlagURG)
		}

		if got.FlagACK() != c.want.FlagACK {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagACK() mismatch, got: %t, want %t", i, got.FlagACK(), c.want.FlagACK)
		}

		if got.FlagPSH() != c.want.FlagPSH {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagPSH() mismatch, got: %t, want %t", i, got.FlagPSH(), c.want.FlagPSH)
		}

		if got.FlagRST() != c.want.FlagRST {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagRST() mismatch, got: %t, want %t", i, got.FlagRST(), c.want.FlagRST)
		}

		if got.FlagSYN() != c.want.FlagSYN {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagSYN() mismatch, got: %t, want %t", i, got.FlagSYN(), c.want.FlagSYN)
		}

		if got.FlagFIN() != c.want.FlagFIN {
			t.Errorf("NewTcpFrameHeaderTest[%d].FlagFIN() mismatch, got: %t, want %t", i, got.FlagFIN(), c.want.FlagFIN)
		}

		if got.WindowSize() != c.want.WindowSize {
			t.Errorf("NewTcpFrameHeaderTest[%d].WindowSize() mismatch, got: %d, want %d", i, got.WindowSize(), c.want.WindowSize)
		}

		if got.Checksum() != c.want.Checksum {
			t.Errorf("NewTcpFrameHeaderTest[%d].Checksum() mismatch, got: %d, want %d", i, got.Checksum(), c.want.Checksum)
		}

		if got.UrgentPointer() != c.want.UrgentPointer {
			t.Errorf("NewTcpFrameHeaderTest[%d].UrgentPointer() mismatch, got: %d, want %d", i, got.UrgentPointer(), c.want.UrgentPointer)
		}
	}
}
