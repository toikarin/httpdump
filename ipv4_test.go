package main

import (
	"testing"
)

type TestIPv4FrameHeaderResult struct {
	Version            uint8
	HeaderLength       uint8
	DSCP               uint8
	ECN                uint8
	TotalLength        uint16
	Identification     uint16
	Flags              uint8
	DontFragment       bool
	MoreFragments      bool
	FragmentOffset     uint16
	TimeToLive         uint8
	Protocol           uint8
	HeaderChecksum     uint16
	SourceAddress      uint32
	DestinationAddress uint32
}

func TestIPv4Parsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestIPv4FrameHeaderResult
	}{
		{[]byte{
			0x45,       // Version + HeaderLength
			0x00,       // DSCP + ECN
			0x00, 0x3C, // TotalLength
			0xEE, 0xE4, // Identification
			0x40, 0x00, // Flags + FragmentOffset
			0x40,       // TTL
			0x06,       // Protocol
			0xB5, 0xb7, // Header Checksum
			0xc0, 0xa8, 0x01, 0x32, // Source Address
			0x54, 0xf8, 0x7f, 0x4d, // Destination Address
		}, TestIPv4FrameHeaderResult{
			Version:            4,
			HeaderLength:       20,
			DSCP:               0,
			ECN:                0,
			TotalLength:        60,
			Identification:     61156,
			Flags:              2,
			DontFragment:       true,
			MoreFragments:      false,
			FragmentOffset:     0,
			TimeToLive:         64,
			Protocol:           PROTOCOL_TCP,
			HeaderChecksum:     0xB5B7,
			SourceAddress:      0xC0A80132,
			DestinationAddress: 0x54F87F4D,
		}},
		{[]byte{
			0x4F,       // Version + HeaderLength
			0x00,       // DSCP + ECN
			0x01, 0x01, // TotalLength
			0xEE, 0xE4, // Identification
			0x20, 0x00, // Flags + FragmentOffset
			0x80,       // TTL
			0x11,       // Protocol
			0xB5, 0xb7, // Header Checksum
			0xAC, 0x0, 0x00, 0x1, // Source Address
			0xAC, 0x0, 0x00, 0x2, // Destination Address
		}, TestIPv4FrameHeaderResult{
			Version:            4,
			HeaderLength:       60,
			DSCP:               0,
			ECN:                0,
			TotalLength:        257,
			Identification:     61156,
			Flags:              1,
			DontFragment:       false,
			MoreFragments:      true,
			FragmentOffset:     0,
			TimeToLive:         128,
			Protocol:           PROTOCOL_UDP,
			HeaderChecksum:     0xB5B7,
			SourceAddress:      0xAC000001,
			DestinationAddress: 0xAC000002,
		}},
	}

	for i, c := range cases {
		got, _ := NewIPv4FrameHeader(c.in)

		if got.Version() != c.want.Version {
			t.Errorf("NewIPv4FrameHeaderTest[%d].Version() mismatch, got: %d, want %d", i, got.Version(), c.want.Version)
		}

		if got.HeaderLength() != c.want.HeaderLength {
			t.Errorf("NewIPv4FrameHeaderTest[%d].HeaderLength() mismatch, got: %d, want %d", i, got.HeaderLength(), c.want.HeaderLength)
		}

		if got.DSCP() != c.want.DSCP {
			t.Errorf("NewIPv4FrameHeaderTest[%d].DSCP() mismatch, got: %d, want %d", i, got.DSCP(), c.want.DSCP)
		}

		if got.ECN() != c.want.ECN {
			t.Errorf("NewIPv4FrameHeaderTest[%d].ECN() mismatch, got: %d, want %d", i, got.ECN(), c.want.ECN)
		}

		if got.TotalLength() != c.want.TotalLength {
			t.Errorf("NewIPv4FrameHeaderTest[%d].TotalLength() mismatch, got: %d, want %d", i, got.TotalLength(), c.want.TotalLength)
		}

		if got.Identification() != c.want.Identification {
			t.Errorf("NewIPv4FrameHeaderTest[%d].Identification() mismatch, got: %d, want %d", i, got.Identification(), c.want.Identification)
		}

		if got.Flags() != c.want.Flags {
			t.Errorf("NewIPv4FrameHeaderTest[%d].Flags() mismatch, got: %d, want %d", i, got.Flags(), c.want.Flags)
		}

		if got.DontFragment() != c.want.DontFragment {
			t.Errorf("NewIPv4FrameHeaderTest[%d].DontFragment() mismatch, got: %t, want %t", i, got.DontFragment(), c.want.DontFragment)
		}

		if got.MoreFragments() != c.want.MoreFragments {
			t.Errorf("NewIPv4FrameHeaderTest[%d].MoreFragments() mismatch, got: %t, want %t", i, got.MoreFragments(), c.want.MoreFragments)
		}

		if got.FragmentOffset() != c.want.FragmentOffset {
			t.Errorf("NewIPv4FrameHeaderTest[%d].FragmentOffset() mismatch, got: %d, want %d", i, got.FragmentOffset(), c.want.FragmentOffset)
		}

		if got.TimeToLive() != c.want.TimeToLive {
			t.Errorf("NewIPv4FrameHeaderTest[%d].TimeToLive() mismatch, got: %d, want %d", i, got.TimeToLive(), c.want.TimeToLive)
		}

		if got.Protocol() != c.want.Protocol {
			t.Errorf("NewIPv4FrameHeaderTest[%d].Protocol() mismatch, got: %d, want %d", i, got.Protocol(), c.want.Protocol)
		}

		if got.HeaderChecksum() != c.want.HeaderChecksum {
			t.Errorf("NewIPv4FrameHeaderTest[%d].HeaderChecksum() mismatch, got: 0x%x, want 0x%x", i, got.HeaderChecksum(), c.want.HeaderChecksum)
		}

		if got.SourceAddress() != c.want.SourceAddress {
			t.Errorf("NewIPv4FrameHeaderTest[%d].SourceAddress() mismatch, got: 0x%x, want 0x%x", i, got.SourceAddress(), c.want.SourceAddress)
		}

		if got.DestinationAddress() != c.want.DestinationAddress {
			t.Errorf("NewIPv4FrameHeaderTest[%d].DestinationAddress() mismatch, got: 0x%x, want 0x%x", i, got.DestinationAddress(), c.want.DestinationAddress)
		}
	}
}
