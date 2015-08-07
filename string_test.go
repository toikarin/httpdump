package main

import (
	"testing"
)

func TestIPV6(t *testing.T) {
	cases := []struct {
		in   []uint16
		want string
	}{
		{[]uint16{0, 0, 0, 0, 0, 0, 0, 0}, "::"},
		{[]uint16{0, 0, 0, 0, 0, 0, 0, 0x1}, "::1"},
		{[]uint16{0x1, 0, 0, 0, 0, 0, 0, 0}, "1::"},
		{[]uint16{0xFF01, 0, 0, 0, 0, 0, 0, 0x101}, "ff01::101"},
		{[]uint16{0xFF01, 0, 0, 0, 0x1, 0, 0, 0x101}, "ff01::1:0:0:101"},
		{[]uint16{0xFF01, 0, 0, 0x1, 0, 0, 0, 0x101}, "ff01:0:0:1::101"},
		{[]uint16{0x2001, 0xDB8, 0, 0, 0x8, 0x800, 0x200C, 0x417a}, "2001:db8::8:800:200c:417a"},
	}

	for _, c := range cases {
		got := IPv6String(c.in)
		if got != c.want {
			t.Errorf("IPv6String(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}
