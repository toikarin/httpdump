package main

import (
	"time"
)

type TCPPacketListener struct {
	tcpStack *TCPStack
}

func (l *TCPPacketListener) NewPacket(timestamp time.Time, linkLayer, networkLayer, transportLayer interface{}) {
	if transportLayer != nil {
		switch transportLayer.(type) {
		case *TCPFrame:
			tcpFrame := transportLayer.(*TCPFrame)
			nl := networkLayer
			l.tcpStack.NewPacket(&nl, tcpFrame)
		}
	}
}
