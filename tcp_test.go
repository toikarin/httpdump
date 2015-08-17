package main

import (
	"testing"
)

type TestTCPFrameHeaderResult struct {
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

func TestTCPParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestTCPFrameHeaderResult
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
		}, TestTCPFrameHeaderResult{
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
		got, err := NewTCPFrameHeader(c.in)
		if err != nil {
			t.Fatal(err)
		}

		if got.SourcePort() != c.want.SourcePort {
			t.Errorf("NewTCPFrameHeaderTest[%d].SourcePort() mismatch, got: %d, want %d", i, got.SourcePort(), c.want.SourcePort)
		}

		if got.DestinationPort() != c.want.DestinationPort {
			t.Errorf("NewTCPFrameHeaderTest[%d].DestinationPort() mismatch, got: %d, want %d", i, got.DestinationPort(), c.want.DestinationPort)
		}

		if got.SequenceNumber() != c.want.SequenceNumber {
			t.Errorf("NewTCPFrameHeaderTest[%d].SequenceNumber() mismatch, got: %d, want %d", i, got.SequenceNumber(), c.want.SequenceNumber)
		}

		if got.AcknowledgeNumber() != c.want.AcknowledgeNumber {
			t.Errorf("NewTCPFrameHeaderTest[%d].AcknowledgeNumber() mismatch, got: %d, want %d", i, got.AcknowledgeNumber(), c.want.AcknowledgeNumber)
		}

		if got.DataOffset() != c.want.DataOffset {
			t.Errorf("NewTCPFrameHeaderTest[%d].DataOffset() mismatch, got: %d, want %d", i, got.DataOffset(), c.want.DataOffset)
		}

		if got.Flags() != c.want.Flags {
			t.Errorf("NewTCPFrameHeaderTest[%d].Flags() mismatch, got: %d, want %d", i, got.Flags(), c.want.Flags)
		}

		if got.FlagNS() != c.want.FlagNS {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagNS() mismatch, got: %t, want %t", i, got.FlagNS(), c.want.FlagNS)
		}

		if got.FlagCWR() != c.want.FlagCWR {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagCWR() mismatch, got: %t, want %t", i, got.FlagCWR(), c.want.FlagCWR)
		}

		if got.FlagECE() != c.want.FlagECE {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagECE() mismatch, got: %t, want %t", i, got.FlagECE(), c.want.FlagECE)
		}

		if got.FlagURG() != c.want.FlagURG {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagURG() mismatch, got: %t, want %t", i, got.FlagURG(), c.want.FlagURG)
		}

		if got.FlagACK() != c.want.FlagACK {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagACK() mismatch, got: %t, want %t", i, got.FlagACK(), c.want.FlagACK)
		}

		if got.FlagPSH() != c.want.FlagPSH {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagPSH() mismatch, got: %t, want %t", i, got.FlagPSH(), c.want.FlagPSH)
		}

		if got.FlagRST() != c.want.FlagRST {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagRST() mismatch, got: %t, want %t", i, got.FlagRST(), c.want.FlagRST)
		}

		if got.FlagSYN() != c.want.FlagSYN {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagSYN() mismatch, got: %t, want %t", i, got.FlagSYN(), c.want.FlagSYN)
		}

		if got.FlagFIN() != c.want.FlagFIN {
			t.Errorf("NewTCPFrameHeaderTest[%d].FlagFIN() mismatch, got: %t, want %t", i, got.FlagFIN(), c.want.FlagFIN)
		}

		if got.WindowSize() != c.want.WindowSize {
			t.Errorf("NewTCPFrameHeaderTest[%d].WindowSize() mismatch, got: %d, want %d", i, got.WindowSize(), c.want.WindowSize)
		}

		if got.Checksum() != c.want.Checksum {
			t.Errorf("NewTCPFrameHeaderTest[%d].Checksum() mismatch, got: %d, want %d", i, got.Checksum(), c.want.Checksum)
		}

		if got.UrgentPointer() != c.want.UrgentPointer {
			t.Errorf("NewTCPFrameHeaderTest[%d].UrgentPointer() mismatch, got: %d, want %d", i, got.UrgentPointer(), c.want.UrgentPointer)
		}
	}
}
