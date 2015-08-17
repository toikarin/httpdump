package main

import (
	"fmt"
	"runtime"
	"time"
)

type Monitor struct {
	stop chan bool

	tcpStack     *TCPStack
	httpListener *HttpTCPListener
}

func NewMonitor(tcpStack *TCPStack, httpListener *HttpTCPListener) *Monitor {
	return &Monitor{
		tcpStack:     tcpStack,
		httpListener: httpListener,
		stop:         make(chan bool),
	}
}

func (m *Monitor) RunPeriodic() {
	ticker := time.NewTicker(10 * time.Second)

	for {
		select {
		case <-m.stop:
			break
		case <-ticker.C:
			m.WriteStats()
		}
	}

	ticker.Stop()
	close(m.stop)
}

func (m *Monitor) WriteStats() {
	tcpStackTotal := 0
	httpListenerTotal := 0

	for range m.tcpStack.connections {
		tcpStackTotal += 1
	}

	for range m.httpListener.conns {
		httpListenerTotal += 1
	}

	fmt.Println("tcp stack total connections:", tcpStackTotal)
	fmt.Println("http listener total connections:", httpListenerTotal)
	fmt.Println("num of goroutines:", runtime.NumGoroutine())
}

func (m *Monitor) Close() {
	m.stop <- true
}
