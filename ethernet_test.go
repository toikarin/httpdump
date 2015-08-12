package main

import (
	"testing"
)

type TestEthernetFrameHeaderResult struct {
	Destination []byte
	Source      []byte
	Type        uint16
}

func TestEthernetParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestEthernetFrameHeaderResult
	}{
		{[]byte{
			0x80, 0x00, 0x20, // Destination MAC address
			0x7A, 0x3F, 0x3E, // Destination MAC address
			0x80, 0x00, 0x20, // Source MAC address
			0x20, 0x3A, 0xAE, // Source MAC address
			0x08, 0x00, // Type
		}, TestEthernetFrameHeaderResult{
			Destination: []byte{0x80, 0x00, 0x20, 0x7A, 0x3F, 0x3E},
			Source:      []byte{0x80, 0x00, 0x20, 0x20, 0x3A, 0xAE},
			Type:        ETHERTYPE_IPV4,
		}},
	}

	for i, c := range cases {
		got, _ := NewEthernetFrameHeader(c.in)

		for i, addressPart := range got.Source() {
			if addressPart != c.want.Source[i] {
				t.Errorf("NewIPv6FrameHeaderTest[%d].Source() mismatch, got: %d, want %d", i, got.Source(), c.want.Source)
				break
			}
		}

		for i, addressPart := range got.Destination() {
			if addressPart != c.want.Destination[i] {
				t.Errorf("NewIPv6FrameHeaderTest[%d].Destination() mismatch, got: %d, want %d", i, got.Destination(), c.want.Destination)
				break
			}
		}

		if got.Type() != c.want.Type {
			t.Errorf("NewEthernetFrameHeaderTest[%d].Type() mismatch, got: %d, want %d", i, got.Type(), c.want.Type)
		}
	}
}
