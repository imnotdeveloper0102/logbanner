package parser

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"time"
)

type jsonParser struct{}

// Parse reads one JSON object log line. Known fields are mapped onto
// the Event; anything else is kept in Extra. Missing fields are
// tolerated and stay at their zero value.
func (jsonParser) Parse(source, line string) (Event, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Event{}, fmt.Errorf("invalid JSON log line: %w", err)
	}
	ev := Event{Source: source, Raw: line, Extra: map[string]any{}}
	for key, value := range raw {
		switch key {
		case "ip":
			if s, ok := value.(string); ok {
				ev.IP = net.ParseIP(s)
			}
		case "method":
			ev.Method, _ = value.(string)
		case "path":
			ev.Path, _ = value.(string)
		case "status":
			ev.Status = jsonNumber(value)
		case "user_agent":
			ev.UserAgent, _ = value.(string)
		case "user":
			ev.User, _ = value.(string)
		case "message":
			ev.Message, _ = value.(string)
		case "timestamp":
			ev.OccurredAt = jsonTime(value)
		default:
			ev.Extra[key] = value
		}
	}
	if len(ev.Extra) == 0 {
		ev.Extra = nil
	}
	return ev, nil
}

// jsonNumber converts a JSON number (decoded as float64), an integer,
// or a numeric string to int; anything else yields 0.
func jsonNumber(value any) int {
	switch v := value.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0
		}
		return n
	default:
		return 0
	}
}

// jsonTime parses a timestamp value: an RFC3339 string, or a Unix
// epoch in seconds (values above 1e12 are treated as milliseconds).
// An unrecognised value yields the zero time rather than failing the
// whole line.
func jsonTime(value any) time.Time {
	switch v := value.(type) {
	case string:
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
		return time.Time{}
	case float64:
		if v > 1e12 {
			return time.UnixMilli(int64(v))
		}
		return time.Unix(int64(v), 0)
	default:
		return time.Time{}
	}
}
