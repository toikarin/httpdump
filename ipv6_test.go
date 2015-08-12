package main

import (
	"testing"
)

type TestIPv6FrameHeaderResult struct {
	Version            uint8
	TrafficClass       uint16
	FlowControl        uint32
	PayloadLength      uint16
	Protocol           uint8
	HopLimit           uint8
	SourceAddress      []uint16
	DestinationAddress []uint16
}

func TestIPv6Parsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestIPv6FrameHeaderResult
	}{
		{[]byte{
			0x60, 0x00, 0x00, 0x00, // Version + TrafficClass + FlowControl
			0x00, 0x28, // Payload Length
			0x06,                   // Next Header
			0x40,                   // Hop Limit
			0x00, 0x00, 0x00, 0x00, // Source Address
			0x00, 0x00, 0x00, 0x00, // Source Address
			0x00, 0x00, 0x00, 0x00, // Source Address
			0x00, 0x00, 0x00, 0x01, // Source Address
			0x20, 0x01, 0x0D, 0xB8, // Destination Address
			0x00, 0x00, 0x00, 0x00, // Destination Address
			0x00, 0x08, 0x08, 0x00, // Destination Address
			0x20, 0x0C, 0x41, 0x7a, // Destination Address
		}, TestIPv6FrameHeaderResult{
			Version:       6,
			TrafficClass:  0,
			FlowControl:   0,
			PayloadLength: 40,
			Protocol:      PROTOCOL_TCP,
			HopLimit:      64,
			SourceAddress: []uint16{
				0, 0, 0, 0, 0, 0, 0, 1,
			},
			DestinationAddress: []uint16{
				8193, 3512, 0, 0, 8, 2048, 8204, 16762,
			},
		}},
	}

	for i, c := range cases {
		got, _ := NewIPv6FrameHeader(c.in)

		if got.Version() != c.want.Version {
			t.Errorf("NewIPv6FrameHeaderTest[%d].Version() mismatch, got: %d, want %d", i, got.Version(), c.want.Version)
		}

		if got.TrafficClass() != c.want.TrafficClass {
			t.Errorf("NewIPv6FrameHeaderTest[%d].TrafficClass() mismatch, got: %d, want %d", i, got.TrafficClass(), c.want.TrafficClass)
		}

		if got.FlowControl() != c.want.FlowControl {
			t.Errorf("NewIPv6FrameHeaderTest[%d].FlowControl() mismatch, got: %d, want %d", i, got.FlowControl(), c.want.FlowControl)
		}

		if got.PayloadLength() != c.want.PayloadLength {
			t.Errorf("NewIPv6FrameHeaderTest[%d].PayloadLength() mismatch, got: %d, want %d", i, got.PayloadLength(), c.want.PayloadLength)
		}

		if got.Protocol() != c.want.Protocol {
			t.Errorf("NewIPv6FrameHeaderTest[%d].Protocol() mismatch, got: %d, want %d", i, got.Protocol(), c.want.Protocol)
		}

		if got.HopLimit() != c.want.HopLimit {
			t.Errorf("NewIPv6FrameHeaderTest[%d].HopLimit() mismatch, got: %d, want %d", i, got.HopLimit(), c.want.HopLimit)
		}

		for i, addressPart := range got.SourceAddress() {
			if addressPart != c.want.SourceAddress[i] {
				t.Errorf("NewIPv6FrameHeaderTest[%d].SourceAddress() mismatch, got: %d, want %d", i, got.SourceAddress(), c.want.SourceAddress)
				break
			}
		}

		for i, addressPart := range got.DestinationAddress() {
			if addressPart != c.want.DestinationAddress[i] {
				t.Errorf("NewIPv6FrameHeaderTest[%d].DestinationAddress() mismatch, got: %d, want %d", i, got.DestinationAddress(), c.want.DestinationAddress)
				break
			}
		}
	}
}
