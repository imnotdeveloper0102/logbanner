package parser

import (
	"fmt"
	"net"
	"regexp"
	"time"
)

// syslogRe matches the syslog envelope of an sshd line:
//
//	Nov  7 10:15:32 host sshd[1234]: Failed password for ...
//
// Groups: 1 month, 2 day, 3 clock, 4 message. Syslog carries no year,
// so the current year is assumed; a log line from late December read
// in early January will land in the wrong year, which stage 3 treats
// as an old event rather than a fresh one.
var syslogRe = regexp.MustCompile(`^(\w{3})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2}) \S+ sshd\[\d+\]: (.*)$`)

// ipRe finds an IPv4 address inside an otherwise unrecognised sshd
// message, so the event still carries the address when it has one.
var ipRe = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

type sshOutcome struct {
	re      *regexp.Regexp
	outcome string
	// userGroup and ipGroup are the regex group numbers holding the
	// user and the IP. A group of 0 means the pattern has no such group.
	userGroup int
	ipGroup   int
	// methodGroup holds the auth method (password/publickey), 0 if none.
	methodGroup int
}

// sshPatterns are tried in order; the first match wins.
var sshPatterns = []sshOutcome{
	{
		re:          regexp.MustCompile(`^Failed (password|publickey) for (?:invalid user )?(\S+) from (\S+) port \d+`),
		outcome:     "failed",
		methodGroup: 1, userGroup: 2, ipGroup: 3,
	},
	{
		re:          regexp.MustCompile(`^Accepted (password|publickey) for (\S+) from (\S+) port \d+`),
		outcome:     "accepted",
		methodGroup: 1, userGroup: 2, ipGroup: 3,
	},
	{
		re:        regexp.MustCompile(`^Invalid user (\S+) from (\S+)`),
		outcome:   "invalid_user",
		userGroup: 1, ipGroup: 2,
	},
	{
		re:        regexp.MustCompile(`^Connection closed by authenticating user (\S+) (\S+) port \d+`),
		outcome:   "closed",
		userGroup: 1, ipGroup: 2,
	},
	{
		re:        regexp.MustCompile(`^Disconnected from authenticating user (\S+) (\S+) port \d+`),
		outcome:   "disconnected",
		userGroup: 1, ipGroup: 2,
	},
	{
		re:      regexp.MustCompile(`^Connection closed by (\S+) port \d+`),
		outcome: "closed",
		ipGroup: 1,
	},
}

type sshParser struct{}

func (sshParser) Parse(source, line string) (Event, error) {
	m := syslogRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, fmt.Errorf("line does not match sshd syslog format")
	}
	occurredAt, err := time.Parse("Jan _2 15:04:05", m[1]+" "+m[2]+" "+m[3])
	if err != nil {
		return Event{}, fmt.Errorf("parse syslog timestamp %q: %w", m[1]+" "+m[2]+" "+m[3], err)
	}
	occurredAt = occurredAt.AddDate(time.Now().Year(), 0, 0)

	msg := m[4]
	ev := Event{
		OccurredAt: occurredAt,
		Source:     source,
		Message:    msg,
		Raw:        line,
		Extra:      map[string]any{},
	}
	for _, p := range sshPatterns {
		pm := p.re.FindStringSubmatch(msg)
		if pm == nil {
			continue
		}
		ev.Extra["outcome"] = p.outcome
		if p.methodGroup > 0 {
			ev.Extra["auth_method"] = pm[p.methodGroup]
		}
		if p.userGroup > 0 {
			ev.User = pm[p.userGroup]
		}
		if p.ipGroup > 0 {
			ev.IP = net.ParseIP(pm[p.ipGroup])
		}
		ev.Message = p.outcome
		return ev, nil
	}
	// Unknown sshd message: still an event, with the raw message and
	// any IP it mentions, so nothing the daemon wrote is silently lost.
	if ip := ipRe.FindString(msg); ip != "" {
		ev.IP = net.ParseIP(ip)
	}
	return ev, nil
}
