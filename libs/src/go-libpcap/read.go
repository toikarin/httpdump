package pcap

import (
	"io"
)

type Stream struct {
	r  io.Reader
	fh *FileHeader
}

func NewStream(r io.Reader) (*Stream, *FileHeader, error) {
	s := &Stream{r, nil}

	header, err := s.readFileHeader()
	if err != nil {
		return nil, nil, err
	}

	s.fh = header

	return s, header, nil
}

func (s *Stream) NextPacket() (*PacketHeader, []byte, error) {
	//
	// Read pcap packet header
	//
	buf, err := s.read(16)
	if err != nil {
		return nil, nil, err
	}

	header, err := s.newPacketHeader(buf)
	if err != nil {
		return nil, nil, err
	}

	//
	// Read rest of the packet
	//
	packetData, err := s.read(int64(header.IncludeLength()))
	if err != nil {
		return nil, nil, err
	}

	return header, packetData, nil
}

func (s *Stream) newPacketHeader(data []byte) (*PacketHeader, error) {
	return &PacketHeader{
		data: data,
		bo:   s.fh.ByteOrder,
	}, nil
}

func (s *Stream) readFileHeader() (header *FileHeader, err error) {
	buf, err := s.read(24)
	if err != nil {
		return nil, err
	}

	return NewFileHeader(buf)
}

func (s *Stream) read(n int64) (buf []byte, err error) {
	buf = make([]byte, n)

	if _, err = io.ReadFull(s.r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}
