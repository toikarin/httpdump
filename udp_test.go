package main

import (
	"testing"
)

type TestUDPFrameHeaderResult struct {
	SourcePort      uint16
	DestinationPort uint16
	Length          uint16
	Checksum        uint16
}

func TestUDPParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestUDPFrameHeaderResult
	}{
		{[]byte{
			0x00, 0x44, // Source Port
			0x00, 0x43, // Destination Port
			0x01, 0x34, // Length
			0xef, 0x1a, // Checksum
		}, TestUDPFrameHeaderResult{
			SourcePort:      68,
			DestinationPort: 67,
			Length:          308,
			Checksum:        0xef1a,
		}},
	}

	for i, c := range cases {
		got, _ := NewUDPFrameHeader(c.in)

		if got.SourcePort() != c.want.SourcePort {
			t.Errorf("NewUDPFrameHeaderTest[%d].SourcePort() mismatch, got: %d, want %d", i, got.SourcePort(), c.want.SourcePort)
		}

		if got.DestinationPort() != c.want.DestinationPort {
			t.Errorf("NewUDPFrameHeaderTest[%d].DestinationPort() mismatch, got: %d, want %d", i, got.DestinationPort(), c.want.DestinationPort)
		}

		if got.Length() != c.want.Length {
			t.Errorf("NewUDPFrameHeaderTest[%d].Length() mismatch, got: %d, want %d", i, got.Length(), c.want.Length)
		}

		if got.Checksum() != c.want.Checksum {
			t.Errorf("NewUDPFrameHeaderTest[%d].Checksum() mismatch, got: %d, want %d", i, got.Checksum(), c.want.Checksum)
		}
	}
}
