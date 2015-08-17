package main

import (
	"testing"
)

func TestIPV6(t *testing.T) {
	cases := []struct {
		in   IPv6Address
		want string
	}{
		{IPv6Address{0, 0, 0, 0, 0, 0, 0, 0}, "::"},
		{IPv6Address{0, 0, 0, 0, 0, 0, 0, 0x1}, "::1"},
		{IPv6Address{0x1, 0, 0, 0, 0, 0, 0, 0}, "1::"},
		{IPv6Address{0xFF01, 0, 0, 0, 0, 0, 0, 0x101}, "ff01::101"},
		{IPv6Address{0xFF01, 0, 0, 0, 0x1, 0, 0, 0x101}, "ff01::1:0:0:101"},
		{IPv6Address{0xFF01, 0, 0, 0x1, 0, 0, 0, 0x101}, "ff01:0:0:1::101"},
		{IPv6Address{0x2001, 0xDB8, 0, 0, 0x8, 0x800, 0x200C, 0x417a}, "2001:db8::8:800:200c:417a"},
	}

	for _, c := range cases {
		got := IPv6String(c.in)
		if got != c.want {
			t.Errorf("IPv6String(%q) == %q, want %q", c.in, got, c.want)
		}
	}
}
