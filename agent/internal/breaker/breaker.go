// Package breaker stops a runaway agent from banning the world.
//
// The breaker counts automatic bans in a sliding window. When more
// than MaxBans auto-bans land inside Window, it opens: further
// auto-bans are refused until Cooldown has passed since it opened,
// when the next auto-ban attempt re-arms it and counting starts
// over. Only automatic (detection) bans are counted or refused;
// a manual ban by an admin is an explicit decision and bypasses
// the breaker entirely. The breaker holds no database state —
// the caller publishes and persists the trip/re-arm events — so
// a restart starts it closed with an empty window.
package breaker

import (
	"sync"
	"time"
)

// Breaker tracks auto-bans in a sliding window.
type Breaker struct {
	mu       sync.Mutex
	max      int
	window   time.Duration
	cooldown time.Duration
	stamps   []time.Time
	open     bool
	openedAt time.Time
}

// New returns a Breaker that trips after more than max auto-bans
// inside window, and re-arms cooldown after it opened.
func New(max, windowSeconds, cooldownSeconds int) *Breaker {
	return &Breaker{
		max:      max,
		window:   time.Duration(windowSeconds) * time.Second,
		cooldown: time.Duration(cooldownSeconds) * time.Second,
	}
}

// Allow reports whether an auto-ban may proceed right now. When the
// breaker is open and the cooldown has passed, the next attempt
// re-arms it: the window is cleared and the ban is allowed, and
// rearmed is true so the caller can log and publish the re-arm.
func (b *Breaker) Allow(now time.Time) (allow, rearmed bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return true, false
	}
	if now.Sub(b.openedAt) < b.cooldown {
		return false, false
	}
	b.open = false
	b.stamps = nil
	return true, true
}

// Record notes one auto-ban that was actually created, and reports
// whether that ban tripped the breaker. Bans refused earlier (by
// the breaker itself, the whitelist, or the max-bans cap) are never
// recorded, so the count is bans in force, not attempts.
func (b *Breaker) Record(now time.Time) (tripped bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.open {
		return false
	}
	b.stamps = append(b.stamps, now)
	cutoff := now.Add(-b.window)
	kept := b.stamps[:0]
	for _, t := range b.stamps {
		if !t.Before(cutoff) {
			kept = append(kept, t)
		}
	}
	b.stamps = kept
	if len(b.stamps) > b.max {
		b.open = true
		b.openedAt = now
		return true
	}
	return false
}

// State returns the current breaker state for logging and the
// summary line: whether it is open, when it opened, and how many
// auto-bans are inside the window right now.
func (b *Breaker) State(now time.Time) (open bool, openedAt time.Time, inWindow int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	cutoff := now.Add(-b.window)
	n := 0
	for _, t := range b.stamps {
		if !t.Before(cutoff) {
			n++
		}
	}
	return b.open, b.openedAt, n
}

// Max returns the configured trip threshold, Window the window, and
// Cooldown the re-arm delay, so event payloads can carry them.
func (b *Breaker) Max() int                { return b.max }
func (b *Breaker) Window() time.Duration   { return b.window }
func (b *Breaker) Cooldown() time.Duration { return b.cooldown }
