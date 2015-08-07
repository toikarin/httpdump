package main

import (
	"encoding/binary"
	"io"
)

func readPcapFileHeader(r io.Reader) (header *PcapFileHeader, err error) {
	bbuf := make([]byte, PCAP_FILE_HEADER_LENGTH)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return NewPcapFileHeader(bbuf)
}

func readPcapPacketHeader(r io.Reader, bo binary.ByteOrder) (*PcapPacketHeader, error) {
	bbuf := make([]byte, PCAP_PACKET_HEADER_LENGTH)

	if _, err := io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return NewPcapPacketHeader(bbuf, bo)
}

func readPacketData(r io.Reader, packetLen uint32) (data []byte, err error) {
	bbuf := make([]byte, packetLen)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return bbuf, nil
}
