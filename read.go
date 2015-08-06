package main

import (
	"encoding/binary"
	"io"
)

func readIPv4FrameHeader(r io.Reader) (packet *IPv4FrameHeader, err error) {
	bbuf := make([]byte, IPV4_FRAME_HEADER_LEN)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return NewIPv4FrameHeader(bbuf)
}

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

func readTcpFrameHeader(r io.Reader) (header *TcpFrameHeader, err error) {
	bbuf := make([]byte, TCP_FRAME_HEADER_LENGTH)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return NewTcpFrameHeader(bbuf)
}

func readTcpOptions(r io.Reader, optionsLen uint8) (err error) {
	bbuf := make([]byte, optionsLen)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return err
	}

	return nil
}

func readEthernetFrameHeader(r io.Reader) (header *EthernetFrameHeader, err error) {
	bbuf := make([]byte, ETHERNET_FRAME_HEADER_LENGTH)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return NewEthernetFrameHeader(bbuf)
}

func readPacketData(r io.Reader, packetLen uint32) (data []byte, err error) {
	bbuf := make([]byte, packetLen)

	if _, err = io.ReadFull(r, bbuf); err != nil {
		return nil, err
	}

	return bbuf, nil
}
