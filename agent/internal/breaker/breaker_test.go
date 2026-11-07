package breaker

import (
	"testing"
	"time"
)

func TestBreakerTripsAfterMax(t *testing.T) {
	b := New(3, 600, 600)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if b.Record(now.Add(time.Duration(i) * time.Second)) {
			t.Fatalf("ban %d tripped the breaker, want no trip at the limit", i+1)
		}
	}
	if !b.Record(now.Add(4 * time.Second)) {
		t.Error("4th ban inside the window did not trip a max-3 breaker")
	}
	if allow, _ := b.Allow(now.Add(5 * time.Second)); allow {
		t.Error("breaker allowed a ban while open")
	}
}

func TestBreakerWindowSlides(t *testing.T) {
	b := New(2, 60, 60)
	start := time.Now()
	b.Record(start)
	b.Record(start.Add(10 * time.Second))
	// Both bans are outside the 60s window by the time the third
	// lands, so it counts as the first ban of a fresh window.
	if b.Record(start.Add(61 * time.Second)) {
		t.Error("ban after the window slid past the earlier bans tripped the breaker")
	}
}

func TestBreakerRearmsAfterCooldown(t *testing.T) {
	b := New(1, 600, 60)
	start := time.Now()
	b.Record(start)
	if !b.Record(start.Add(time.Second)) {
		t.Fatal("second ban did not trip a max-1 breaker")
	}
	if allow, _ := b.Allow(start.Add(30 * time.Second)); allow {
		t.Error("breaker allowed a ban 30s after tripping with a 60s cooldown")
	}
	allow, rearmed := b.Allow(start.Add(61 * time.Second))
	if !allow || !rearmed {
		t.Errorf("Allow after cooldown = (%v, %v), want (true, true)", allow, rearmed)
	}
	// Re-arming clears the window: two fresh bans are needed to trip
	// again, not one.
	if b.Record(start.Add(62 * time.Second)) {
		t.Error("first ban after re-arm tripped the breaker")
	}
	if allow, rearmed := b.Allow(start.Add(63 * time.Second)); !allow || rearmed {
		t.Errorf("Allow after re-arm = (%v, %v), want (true, false)", allow, rearmed)
	}
}

func TestBreakerRecordWhileOpenDoesNotExtend(t *testing.T) {
	b := New(1, 600, 60)
	start := time.Now()
	b.Record(start)
	b.Record(start.Add(time.Second)) // trips
	if b.Record(start.Add(2 * time.Second)) {
		t.Error("recording while open reported a second trip")
	}
	// The re-arm time is still the original trip, not the last
	// record: the breaker must re-arm 60s after tripping.
	if allow, _ := b.Allow(start.Add(61 * time.Second)); !allow {
		t.Error("breaker did not re-arm 60s after the trip")
	}
}

func TestBreakerState(t *testing.T) {
	b := New(5, 600, 600)
	now := time.Now()
	b.Record(now)
	b.Record(now.Add(time.Second))
	open, _, inWindow := b.State(now.Add(2 * time.Second))
	if open || inWindow != 2 {
		t.Errorf("State = open %v inWindow %d, want false 2", open, inWindow)
	}
}
