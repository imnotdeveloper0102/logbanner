package whitelist

import (
	"net"
	"testing"
)

func TestContainsConfiguredRanges(t *testing.T) {
	l, err := New([]string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	whitelisted := []string{"10.1.2.3", "172.16.5.4", "172.31.255.255", "192.168.0.1"}
	for _, s := range whitelisted {
		if !l.Contains(net.ParseIP(s)) {
			t.Errorf("Contains(%s) = false, want true", s)
		}
	}
	notWhitelisted := []string{"8.8.8.8", "172.15.0.1", "172.32.0.1", "192.169.0.1", "203.0.113.5", "2001:db8::1"}
	for _, s := range notWhitelisted {
		if l.Contains(net.ParseIP(s)) {
			t.Errorf("Contains(%s) = true, want false", s)
		}
	}
}

func TestLoopbackAlwaysWhitelisted(t *testing.T) {
	l, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, s := range []string{"127.0.0.1", "127.9.9.9", "::1"} {
		if !l.Contains(net.ParseIP(s)) {
			t.Errorf("Contains(%s) = false, loopback must always be whitelisted", s)
		}
	}
	if l.Contains(net.ParseIP("203.0.113.5")) {
		t.Error("empty whitelist must not whitelist a public IP")
	}
}

func TestAdminIPEntry(t *testing.T) {
	l, err := New([]string{"203.0.113.10"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !l.Contains(net.ParseIP("203.0.113.10")) {
		t.Error("admin IP 203.0.113.10 should be whitelisted")
	}
	if l.Contains(net.ParseIP("203.0.113.11")) {
		t.Error("neighbouring IP 203.0.113.11 should not be whitelisted")
	}
}

func TestIPv6Range(t *testing.T) {
	l, err := New([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !l.Contains(net.ParseIP("2001:db8::1")) {
		t.Error("2001:db8::1 should be whitelisted by 2001:db8::/32")
	}
	if l.Contains(net.ParseIP("2001:db9::1")) {
		t.Error("2001:db9::1 should not be whitelisted")
	}
}

func TestNewRejectsInvalidEntries(t *testing.T) {
	for _, bad := range []string{"not-a-cidr", "10.0.0.0/33", "203.0.113.5/33", "", "  "} {
		if _, err := New([]string{bad}); err == nil {
			t.Errorf("New accepted invalid whitelist entry %q", bad)
		}
	}
}
