package main

import (
	"fmt"
)

type FlowAddress struct {
	SourceAddress interface{}
	SourcePort    uint16

	DestinationAddress interface{}
	DestinationPort    uint16
}

type TCPState uint8

const (
	TCP_STATE_CLIENT_SYN_SENT TCPState = iota
	TCP_STATE_CLIENT_SYN_RECEIVED
	TCP_STATE_CLIENT_ESTABLISHED

	TCP_STATE_SERVER_SYN_RECEIVED
	TCP_STATE_SERVER_ESTABLISHED
)

type Flow struct {
	Address                FlowAddress
	InitialSequenceNumber  uint32
	ExpectedSequenceNumber uint32
	TCPState               TCPState
}

func (f *Flow) SetInitialSequence(s uint32) {
	f.InitialSequenceNumber = s
	f.ExpectedSequenceNumber = s
}

func (f *Flow) RelativeSequenceNumber(s uint32) uint32 {
	if s == 0 {
		return 0
	}

	return s - f.InitialSequenceNumber + 1
}

type BufferedPacket struct {
	NetworkFrame *interface{}
	TCPFrame     *TCPFrame
}

type TCPConnection struct {
	ClientFlow *Flow
	ServerFlow *Flow

	Buffer      map[uint32]*BufferedPacket
}

func (conn *TCPConnection) Flows(flowAddress FlowAddress) (flow *Flow, isClient bool) {
	if conn.ClientFlow.Address == flowAddress {
		return conn.ClientFlow, true
	} else {
		return conn.ServerFlow, false
	}
}

type TCPStack struct {
	connections map[FlowAddress]*TCPConnection
	tcpListener TCPListener
}

func NewTCPStack(tcpListener TCPListener) *TCPStack {
	return &TCPStack{
		connections: make(map[FlowAddress]*TCPConnection),
		tcpListener: tcpListener,
	}
}

func (tcpStack *TCPStack) newConnection(clientFlowAddress FlowAddress, tcpFrame *TCPFrame) *TCPConnection {
	//
	// create flows
	//
	clientFlow := &Flow{clientFlowAddress, 0, 0, TCP_STATE_CLIENT_SYN_SENT}

	serverFlowAddress := FlowAddress{
		SourceAddress:      clientFlowAddress.DestinationAddress,
		SourcePort:         clientFlowAddress.DestinationPort,
		DestinationAddress: clientFlowAddress.SourceAddress,
		DestinationPort:    clientFlowAddress.SourcePort,
	}
	serverFlow := &Flow{serverFlowAddress, 0, 0, TCP_STATE_SERVER_SYN_RECEIVED}

	// create connection
	conn := &TCPConnection{clientFlow, serverFlow, make(map[uint32]*BufferedPacket)}

	// check for existing connection
	_, ok := tcpStack.connections[clientFlowAddress]
	if ok {
		// FIXME: close, clean existing connection
	}

	tcpStack.connections[clientFlowAddress] = conn
	tcpStack.connections[serverFlowAddress] = conn

	return conn
}

type TCPListenerConnection struct {
	ClientAddress interface{}
	ClientPort    uint16

	ServerAddress interface{}
	ServerPort     uint16
}

type TCPListener interface {
	NewConnection(conn TCPListenerConnection)
	Data(conn TCPListenerConnection, data []byte, clientData bool)
	ClosedConnection(conn TCPListenerConnection)
}

func (tcpStack *TCPStack) NewPacket(networkFrame *interface{}, tcpFrame *TCPFrame) {
	var conn *TCPConnection
	newConnection := false
	closedConnection := false
	flowAddress := FlowAddress{
		SourceAddress:      sourceAddress(*networkFrame),
		SourcePort:         tcpFrame.Header.SourcePort(),
		DestinationAddress: destinationAddress(*networkFrame),
		DestinationPort:    tcpFrame.Header.DestinationPort(),
	}

	//
	// find connection
	//
	if tcpFrame.Header.FlagSYN() && !tcpFrame.Header.FlagACK() {
		//
		// create new connection
		//
		conn = tcpStack.newConnection(flowAddress, tcpFrame)
		newConnection = true
	} else {
		var ok bool
		conn, ok = tcpStack.connections[flowAddress]
		if !ok {
			// unknown connection, can happen for example when connection is opened before tcpdump starts.
			fmt.Println("UNKNOWN CONN")
			return
		}
	}

	from, isClient := conn.Flows(flowAddress)
	seq := tcpFrame.Header.SequenceNumber()

	if tcpFrame.Header.FlagSYN() {
		//
		// handle SYN
		//
		from.SetInitialSequence(seq)
	} else {
		//
		// check packet order
		// FIXME: add some kind of thresholds for max diff
		//
		if seq > from.ExpectedSequenceNumber {
			fmt.Println("FUTURE")
			fmt.Println("Expected", from.ExpectedSequenceNumber, "got", seq)
			fmt.Println("diff", seq - from.ExpectedSequenceNumber)
			// future packet
			conn.Buffer[seq] = &BufferedPacket{networkFrame, tcpFrame}
			return
		} else if seq < from.ExpectedSequenceNumber {
			// past packet
			fmt.Println("Expected", from.ExpectedSequenceNumber, "got", seq)
			fmt.Println("diff", seq - from.ExpectedSequenceNumber)
			fmt.Println("PAST PACKET")
			return
		}
	}

	if len(tcpFrame.Payload) > 0 {
		//
		// increment next expected sequence number
		//
		from.ExpectedSequenceNumber += uint32(len(tcpFrame.Payload))
	} else {
		if tcpFrame.Header.FlagSYN() || tcpFrame.Header.FlagFIN() {
			//
			// increment next expected sequence number
			//
			from.ExpectedSequenceNumber += 1
		}
	}

	//
	// Handle FIN
	//
	if tcpFrame.Header.FlagFIN() {
		// FIXME
	}

	//
	// Notify
	//
	tcpListenerConn := TCPListenerConnection{
		ClientAddress:      conn.ClientFlow.Address.SourceAddress,
		ClientPort:         conn.ClientFlow.Address.SourcePort,
		ServerAddress:      conn.ClientFlow.Address.DestinationAddress,
		ServerPort:         conn.ClientFlow.Address.DestinationPort,
	}


	if newConnection {
		tcpStack.tcpListener.NewConnection(tcpListenerConn)
	}
	if len(tcpFrame.Payload) > 0 {
		tcpStack.tcpListener.Data(tcpListenerConn, tcpFrame.Payload, isClient)
	}
	if closedConnection {
		tcpStack.tcpListener.ClosedConnection(tcpListenerConn)
	}

	//
	// handle next buffered packets
	//
	bp, ok := conn.Buffer[from.ExpectedSequenceNumber]
	if ok {
		delete(conn.Buffer, from.ExpectedSequenceNumber)
		tcpStack.NewPacket(bp.NetworkFrame, bp.TCPFrame)
	}
}
