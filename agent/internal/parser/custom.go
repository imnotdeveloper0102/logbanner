package parser

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"time"

	"logbanner/internal/config"
)

type customParser struct {
	format config.CustomFormat
	re     *regexp.Regexp
}

// Parse matches the line against the configured regex and maps its
// named groups onto the Event. A non-matching line, a non-numeric
// status, an invalid IP, or an unparsable time is an error.
func (p customParser) Parse(source, line string) (Event, error) {
	m := p.re.FindStringSubmatch(line)
	if m == nil {
		return Event{}, fmt.Errorf("line does not match custom format %q", p.format.Name)
	}
	ev := Event{Source: source, Raw: line}
	for i, name := range p.re.SubexpNames() {
		if i == 0 || name == "" || m[i] == "" {
			continue
		}
		switch name {
		case "ip":
			ip := net.ParseIP(m[i])
			if ip == nil {
				return Event{}, fmt.Errorf("custom format %q: group ip %q is not a valid IP address", p.format.Name, m[i])
			}
			ev.IP = ip
		case "method":
			ev.Method = m[i]
		case "path":
			ev.Path = m[i]
		case "status":
			status, err := strconv.Atoi(m[i])
			if err != nil {
				return Event{}, fmt.Errorf("custom format %q: group status %q is not a number: %w", p.format.Name, m[i], err)
			}
			ev.Status = status
		case "user_agent":
			ev.UserAgent = m[i]
		case "user":
			ev.User = m[i]
		case "message":
			ev.Message = m[i]
		case "time", "timestamp":
			layout := p.format.TimeFormat
			if layout == "" {
				layout = time.RFC3339
			}
			occurredAt, err := time.Parse(layout, m[i])
			if err != nil {
				return Event{}, fmt.Errorf("custom format %q: parse time %q with layout %q: %w", p.format.Name, m[i], layout, err)
			}
			ev.OccurredAt = occurredAt
		}
	}
	return ev, nil
}
