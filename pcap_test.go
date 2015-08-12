package main

import (
	"encoding/binary"
	"testing"
	"time"
)

type TestPcapFileHeaderResult struct {
	ByteOrder    binary.ByteOrder
	VersionMajor uint16
	VersionMinor uint16
	ThisZone     int32
	Sigfigs      uint32
	SnapLength   uint32
	Network      uint32
}

func TestPcapFileParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		want TestPcapFileHeaderResult
	}{
		{[]byte{
			0xd4, 0xc3, 0xb2, 0xa1, // byte order
			0x02, 0x00, // version major
			0x04, 0x00, // version minor
			0x00, 0x00, 0x00, 0x00, // this zone
			0x00, 0x00, 0x00, 0x00, // sigfigs
			0x00, 0x00, 0x04, 0x00, // snap length
			0x01, 0x00, 0x00, 0x00, // network
		}, TestPcapFileHeaderResult{
			ByteOrder:    binary.LittleEndian,
			VersionMajor: 2,
			VersionMinor: 4,
			ThisZone:     0,
			Sigfigs:      0,
			SnapLength:   262144,
			Network:      1,
		}},
		{[]byte{
			0xa1, 0xb2, 0xc3, 0xd4, // byte order
			0x00, 0x02, // version major
			0x00, 0x04, // version minor
			0x00, 0x00, 0x00, 0x00, // this zone
			0x00, 0x00, 0x00, 0x00, // sigfigs
			0x00, 0x04, 0x00, 0x00, // snap length
			0x00, 0x00, 0x00, 0x01, // network
		}, TestPcapFileHeaderResult{
			ByteOrder:    binary.BigEndian,
			VersionMajor: 2,
			VersionMinor: 4,
			ThisZone:     0,
			Sigfigs:      0,
			SnapLength:   262144,
			Network:      1,
		}},
	}

	for i, c := range cases {
		got, _ := NewPcapFileHeader(c.in)

		if got.ByteOrder != c.want.ByteOrder {
			t.Errorf("NewPcapFileHeaderTest[%d].ByteOrder mismatch, got: %s, want %s", i, got.ByteOrder, c.want.ByteOrder)
		}

		if got.VersionMajor() != c.want.VersionMajor {
			t.Errorf("NewPcapFileHeaderTest[%d].VersionMajor() mismatch, got: %d, want %d", i, got.VersionMajor(), c.want.VersionMajor)
		}

		if got.VersionMinor() != c.want.VersionMinor {
			t.Errorf("NewPcapFileHeaderTest[%d].VersionMinor() mismatch, got: %d, want %d", i, got.VersionMinor(), c.want.VersionMinor)
		}

		if got.ThisZone() != c.want.ThisZone {
			t.Errorf("NewPcapFileHeaderTest[%d].ThisZone() mismatch, got: %d, want %d", i, got.ThisZone(), c.want.ThisZone)
		}

		if got.Sigfigs() != c.want.Sigfigs {
			t.Errorf("NewPcapFileHeaderTest[%d].Sigfigs() mismatch, got: %d, want %d", i, got.Sigfigs(), c.want.Sigfigs)
		}

		if got.SnapLength() != c.want.SnapLength {
			t.Errorf("NewPcapFileHeaderTest[%d].SnapLength() mismatch, got: %d, want %d", i, got.SnapLength(), c.want.SnapLength)
		}

		if got.Network() != c.want.Network {
			t.Errorf("NewPcapFileHeaderTest[%d].Network() mismatch, got: %d, want %d", i, got.Network(), c.want.Network)
		}
	}
}

type TestPcapPacketHeaderResult struct {
	Timestamp      time.Time
	IncludeLength  uint32
	OriginalLength uint32
}

func TestPcapPacketHeaderParsing(t *testing.T) {
	cases := []struct {
		in   []byte
		inBo binary.ByteOrder
		want TestPcapPacketHeaderResult
	}{
		{[]byte{
			0xe0, 0x88, 0xc8, 0x55, // Time Seconds
			0xac, 0x25, 0x03, 0x00, // Time Microseconds
			0x4a, 0x00, 0x00, 0x00, // Include Length
			0x4a, 0x00, 0x00, 0x00, // Original Length
		}, binary.LittleEndian, TestPcapPacketHeaderResult{
			Timestamp:      time.Date(2015, time.August, 10, 11, 20, 0, 206252*1000, time.UTC).Local(),
			IncludeLength:  74,
			OriginalLength: 74,
		}},
		{[]byte{
			0x55, 0xc8, 0x88, 0xe0, // Time Seconds
			0x00, 0x03, 0x25, 0xac, // Time Microseconds
			0x00, 0x00, 0x00, 0x4a, // Include Length
			0x00, 0x00, 0x00, 0x4a, // Original Length
		}, binary.BigEndian, TestPcapPacketHeaderResult{
			Timestamp:      time.Date(2015, time.August, 10, 11, 20, 0, 206252*1000, time.UTC).Local(),
			IncludeLength:  74,
			OriginalLength: 74,
		}},
	}

	for i, c := range cases {
		got, err := NewPcapPacketHeader(c.in, c.inBo)
		if err != nil {
			t.Fatal(err)
		}

		if got.Timestamp() != c.want.Timestamp {
			t.Errorf("NewPcapFileHeaderTest[%d].Timestamp mismatch, got: %s, want %s", i, got.Timestamp(), c.want.Timestamp)
		}

		if got.IncludeLength() != c.want.IncludeLength {
			t.Errorf("NewPcapFileHeaderTest[%d].IncludeLength mismatch, got: %d, want %d", i, got.IncludeLength(), c.want.IncludeLength)
		}

		if got.OriginalLength() != c.want.OriginalLength {
			t.Errorf("NewPcapFileHeaderTest[%d].OriginalLength mismatch, got: %d, want %d", i, got.OriginalLength(), c.want.OriginalLength)
		}
	}
}
