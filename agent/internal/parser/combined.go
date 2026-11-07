package parser

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"
)

// combinedLogRe matches the nginx and Apache combined log format:
//
//	203.0.113.7 - alice [07/Nov/2026:10:15:32 +0700] "GET /index HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
//
// Groups: 1 ip, 2 user, 3 time, 4 method, 5 path, 6 status, 7 user-agent.
// A request of "-" (no request line) leaves method and path empty.
var combinedLogRe = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "(?:(\S+) (\S+)[^"]*|-)" (\d{3}) \S+ "[^"]*" "([^"]*)"`)

type combinedParser struct{}

func (combinedParser) Parse(source, line string) (Event, error) {
	m := combinedLogRe.FindStringSubmatch(line)
	if m == nil {
		return Event{}, fmt.Errorf("line does not match combined log format")
	}
	occurredAt, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[3])
	if err != nil {
		return Event{}, fmt.Errorf("parse log timestamp %q: %w", m[3], err)
	}
	status, err := strconv.Atoi(m[6])
	if err != nil {
		return Event{}, fmt.Errorf("parse status %q: %w", m[6], err)
	}
	ip := net.ParseIP(m[1])
	if ip == nil {
		return Event{}, fmt.Errorf("parse client IP %q: not a valid IP address", m[1])
	}
	user := m[2]
	if user == "-" {
		user = ""
	}
	return Event{
		OccurredAt: occurredAt,
		Source:     source,
		IP:         ip,
		Method:     m[4],
		Path:       m[5],
		Status:     status,
		UserAgent:  m[7],
		User:       user,
		Raw:        line,
	}, nil
}
