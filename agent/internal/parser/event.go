// Package parser turns raw log lines into Events. Each log format has
// one parser; all of them produce the same Event shape so the detector
// in stage 3 never sees format-specific types.
package parser

import (
	"net"
	"time"
)

// Event is one parsed log line. Fields a format does not provide stay
// at their zero value; Extra holds any fields a format carries that
// have no dedicated field here.
type Event struct {
	OccurredAt time.Time
	Source     string
	IP         net.IP
	Method     string
	Path       string
	Status     int
	UserAgent  string
	User       string
	Message    string
	Raw        string
	Extra      map[string]any
}
