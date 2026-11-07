// Package whitelist is the hard whitelist checked before every
// ban, with no exceptions. Loopback (127.0.0.0/8 and ::1) is always
// whitelisted, whatever the config says; the configured entries are
// CIDRs or single IPs (the admin's own IPs go here, alongside the
// internal ranges). A whitelisted IP is never banned, not even on a
// manual ban path later; the caller logs a warning when a detection
// for one is skipped.
package whitelist

import (
	"fmt"
	"net"
	"strings"
)

// List is a parsed whitelist.
type List struct {
	nets []*net.IPNet
}

// New parses entries, each a CIDR ("10.0.0.0/8") or a single IP
// ("203.0.113.10", treated as a /32 or /128). Anything else is an
// error, so a typo in the config fails startup instead of silently
// whitelisting nothing.
func New(entries []string) (*List, error) {
	l := &List{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			return nil, fmt.Errorf("whitelist entry must not be empty")
		}
		if ip := net.ParseIP(e); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			l.nets = append(l.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, fmt.Errorf("whitelist entry %q is not an IP or CIDR: %w", e, err)
		}
		l.nets = append(l.nets, n)
	}
	return l, nil
}

// Len returns how many configured ranges the list holds, not
// counting the built-in loopback range.
func (l *List) Len() int { return len(l.nets) }

// Contains reports whether ip must never be banned.
func (l *List) Contains(ip net.IP) bool {
	if ip == nil {
		return false
	}
	// Loopback is whitelisted unconditionally: banning it would cut
	// the agent off from its own database and the local services.
	if ip.IsLoopback() {
		return true
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
