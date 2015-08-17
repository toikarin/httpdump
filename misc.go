package main

import (
	"fmt"
)

func red(s string) string {
	return "\033[31m" + s + "\033[0m"
}

func yellow(s string) string {
	return "\033[33m" + s + "\033[0m"
}

func blue(s string) string {
	return "\033[94m" + s + "\033[0m"
}

func green(s string) string {
	return "\033[92m" + s + "\033[0m"
}

func sourceAddress(a interface{}) interface{} {
	switch t := a.(type) {
	case *IPv4Frame:
		return a.(*IPv4Frame).Header.SourceAddress()
	case *IPv6Frame:
		return a.(*IPv6Frame).Header.SourceAddress()
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func destinationAddress(a interface{}) interface{} {
	switch t := a.(type) {
	case *IPv4Frame:
		return a.(*IPv4Frame).Header.DestinationAddress()
	case *IPv6Frame:
		return a.(*IPv6Frame).Header.DestinationAddress()
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func sourceAddressToString(a interface{}) string {
	switch t := a.(type) {
	case *IPv4Frame:
		return IPv4String(a.(*IPv4Frame).Header.SourceAddress())
	case IPv4Frame:
		return IPv4String(a.(IPv4Frame).Header.SourceAddress())
	case *IPv6Frame:
		return IPv6String(a.(*IPv6Frame).Header.SourceAddress())
	case IPv6Frame:
		return IPv6String(a.(IPv6Frame).Header.SourceAddress())
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}

func destinationAddressToString(a interface{}) string {
	switch t := a.(type) {
	case *IPv4Frame:
		return IPv4String(a.(*IPv4Frame).Header.DestinationAddress())
	case *IPv6Frame:
		return IPv6String(a.(*IPv6Frame).Header.DestinationAddress())
	default:
		panic(fmt.Sprintf("Unknown frame header type: %T", t))
	}
}
