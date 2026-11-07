package parser

import "sync"

// SourceMetrics counts lines for one log source.
type SourceMetrics struct {
	LinesRead  uint64
	Parsed     uint64
	Unparsable uint64
}

// Snapshot is a point-in-time copy of the metrics, safe to log.
type Snapshot struct {
	LinesRead  uint64
	Parsed     uint64
	Unparsable uint64
	PerSource  map[string]SourceMetrics
}

// Metrics counts lines read, parsed and unparsable, in total and per
// source. It is safe for concurrent use by the tailer consumer.
type Metrics struct {
	mu         sync.Mutex
	linesRead  uint64
	parsed     uint64
	unparsable uint64
	perSource  map[string]*SourceMetrics
}

// NewMetrics returns an empty Metrics.
func NewMetrics() *Metrics {
	return &Metrics{perSource: map[string]*SourceMetrics{}}
}

func (m *Metrics) forSource(source string) *SourceMetrics {
	s, ok := m.perSource[source]
	if !ok {
		s = &SourceMetrics{}
		m.perSource[source] = s
	}
	return s
}

// RecordRead counts one line handed to the parser from source.
func (m *Metrics) RecordRead(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.linesRead++
	m.forSource(source).LinesRead++
}

// RecordParsed counts one line that parsed into an Event.
func (m *Metrics) RecordParsed(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.parsed++
	m.forSource(source).Parsed++
}

// RecordUnparsable counts one line no parser could make sense of.
func (m *Metrics) RecordUnparsable(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.unparsable++
	m.forSource(source).Unparsable++
}

// Snapshot returns a copy of the current counts.
func (m *Metrics) Snapshot() Snapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := Snapshot{
		LinesRead:  m.linesRead,
		Parsed:     m.parsed,
		Unparsable: m.unparsable,
		PerSource:  make(map[string]SourceMetrics, len(m.perSource)),
	}
	for source, s := range m.perSource {
		snap.PerSource[source] = *s
	}
	return snap
}
