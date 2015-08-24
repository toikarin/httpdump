package main

import (
	"time"
)

type MultiPacketListener struct {
	PacketListeners []PacketListener
}

func (mpl *MultiPacketListener) Add(pl PacketListener) {
	mpl.PacketListeners = append(mpl.PacketListeners, pl)
}

func (mpl MultiPacketListener) NewPacket(timestamp time.Time, linkLayer, networkLayer, transportLayer interface{}) {
	for _, pk := range mpl.PacketListeners {
		pk.NewPacket(timestamp, linkLayer, networkLayer, transportLayer)
	}
}
