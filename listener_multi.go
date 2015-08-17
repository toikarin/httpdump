package main

type MultiPacketListener struct {
	PacketListeners []PacketListener
}

func (mpl *MultiPacketListener) Add(pl PacketListener) {
	mpl.PacketListeners = append(mpl.PacketListeners, pl)
}

func (mpl MultiPacketListener) NewPacket(pcapFileHeader PcapFileHeader, pcapPacketHeader PcapPacketHeader, linkLayer, networkLayer, transportLayer interface{}) {
	for _, pk := range mpl.PacketListeners {
		pk.NewPacket(pcapFileHeader, pcapPacketHeader, linkLayer, networkLayer, transportLayer)
	}
}
