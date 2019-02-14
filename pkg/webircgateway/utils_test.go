package webircgateway

import (
	"net"
	"testing"
)

func Test_isPrivateIP(t *testing.T) {
	type args struct {
	}
	tests := []struct {
		ip   net.IP
		want bool
	}{
		{net.ParseIP("127.0.0.1"), true},
		{net.ParseIP("10.0.0.10"), true},
		{net.ParseIP("192.168.33.11"), true},
		{net.ParseIP("192.0.2.1"), false},
		{net.ParseIP("198.51.100.254"), false},
		{net.ParseIP("203.0.113.126"), false},
	}
	for _, tt := range tests {
		t.Run(tt.ip.String(), func(t *testing.T) {
			if got := isPrivateIP(tt.ip); got != tt.want {
				t.Errorf("isPrivateIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_makeClientReplacements(t *testing.T) {

	tests := []struct {
		format string
		want   string
	}{
		{"%h", "example.org"},
		{"%h hostname at start", "example.org hostname at start"},
		{"hostname %h in middle", "hostname example.org in middle"},
		{"hostname at end %h", "hostname at end example.org"},
		{"%i", "7f000001"},
		{"%i ipHex at start", "7f000001 ipHex at start"},
		{"ipHex %i in middle", "ipHex 7f000001 in middle"},
		{"ipHex at end %i", "ipHex at end 7f000001"},
	}
	gateway := NewGateway("gateway")
	client := NewClient(gateway)
	client.RemoteAddr = "127.0.0.1"
	client.RemoteHostname = "example.org"
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			if got := makeClientReplacements(tt.format, client); got != tt.want {
				t.Errorf("makeClientReplacements() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIpv4ToHex(t *testing.T) {
	tests := []struct {
		ip   string
		want string
	}{
		{"192.0.2.1", "c0000201"},
		{"198.51.100.254", "c63364fe"},
		{"203.0.113.126", "cb00717e"},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			if got := Ipv4ToHex(tt.ip); got != tt.want {
				t.Errorf("Ipv4ToHex() = %v, want %v", got, tt.want)
			}
		})
	}
}
