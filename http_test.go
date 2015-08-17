package main

import (
	"testing"
)

func TestIsHttp(t *testing.T) {
	cases := []struct {
		in   []byte
		want bool
	}{
		{[]byte("GET / HTTP/1.0\r\n"), true},
		{[]byte("POST /foobar HTTP/1.1\r\n"), true},
		{[]byte("HTTP/1.1"), false},
		{[]byte("HTTP/1.1\r\n"), false},
		{[]byte("GET HTTP/1.1\r\n"), false},
	}

	for i, c := range cases {
		got := isHttpReq(c.in)

		if got != c.want {
			t.Errorf("TestIsHttp[%d] mismatch for data '%s'. got: %t, want %t", i, string(c.in), got, c.want)
		}
	}
}
