package main

import (
	"testing"
)

type TestICMPFrameHeaderResult struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Content  []byte
}

func TestICMPParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestICMPFrameHeaderResult
	}{
		{[]byte{
			0x08,       // Type
			0x00,       // Code
			0x7d, 0x76, // Checksum
			0x3b, 0x02, 0x00, 0x09, // Content
		}, TestICMPFrameHeaderResult{
			Type:     8,
			Code:     0,
			Checksum: 0x7d76,
			Content:  []byte{0x3b, 0x02, 0x00, 0x09},
		}},
	}

	for i, c := range cases {
		got, _ := NewICMPFrameHeader(c.in)

		if got.Type() != c.want.Type {
			t.Errorf("NewICMPFrameHeaderTest[%d].Type() mismatch, got: %d, want %d", i, got.Type(), c.want.Type)
		}

		if got.Code() != c.want.Code {
			t.Errorf("NewICMPFrameHeaderTest[%d].Code() mismatch, got: %d, want %d", i, got.Code(), c.want.Code)
		}

		if got.Checksum() != c.want.Checksum {
			t.Errorf("NewICMPFrameHeaderTest[%d].Checksum() mismatch, got: %d, want %d", i, got.Checksum(), c.want.Checksum)
		}

		for i, contentPart := range got.Content() {
			if contentPart != c.want.Content[i] {
				t.Errorf("NewUDPFrameHeaderTest[%d].Content() mismatch, got: %d, want %d", i, got.Content(), c.want.Content)
				break
			}
		}
	}
}
