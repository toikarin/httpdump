package main

type TCPPacketListener struct {
	tcpStack *TCPStack
}

func (l *TCPPacketListener) NewPacket(fileHeader PcapFileHeader, pcapPacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	if transportLayer != nil {
		switch transportLayer.(type) {
		case *TCPFrame:
			tcpFrame := transportLayer.(*TCPFrame)
			nl := networkLayer
			l.tcpStack.NewPacket(&nl, tcpFrame)
		}
	}
}
