package tailer

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"logbanner/internal/config"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func appendLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	for _, l := range lines {
		if _, err := f.WriteString(l + "\n"); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
}

// collect waits for n lines or fails the test.
func collect(t *testing.T, ch <-chan Line, n int) []Line {
	t.Helper()
	var got []Line
	timeout := time.After(5 * time.Second)
	for len(got) < n {
		select {
		case l := <-ch:
			got = append(got, l)
		case <-timeout:
			t.Fatalf("timed out waiting for %d lines, got %d: %v", n, len(got), got)
		}
	}
	return got
}

// expectNoLines fails if any line arrives within d.
func expectNoLines(t *testing.T, ch <-chan Line, d time.Duration) {
	t.Helper()
	select {
	case l := <-ch:
		t.Fatalf("unexpected line: %q", l.Text)
	case <-time.After(d):
	}
}

func texts(lines []Line) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l.Text
	}
	return out
}

func TestTailerFollowsAppendRotateTruncateAndRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.log")
	stateDir := filepath.Join(dir, "state")

	// Lines written before the first start are history, not new
	// events, so the tailer must skip them.
	if err := os.WriteFile(path, []byte("old line 1\nold line 2\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := config.Source{Path: path, Format: "nginx"}
	tl, err := New([]config.Source{src}, stateDir, discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tl.PollInterval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	tl.Start(ctx)
	expectNoLines(t, tl.Lines(), 200*time.Millisecond)

	appendLines(t, path, "line 1", "line 2")
	got := collect(t, tl.Lines(), 2)
	if texts(got)[0] != "line 1" || texts(got)[1] != "line 2" {
		t.Fatalf("appended lines = %v", texts(got))
	}
	if got[0].Source != path || got[0].Format != "nginx" {
		t.Fatalf("line metadata = %+v", got[0])
	}

	// Rotation: rename the file away, create a new one. Lines in the
	// new file must be followed; lines appended to the old file must
	// not appear.
	oldPath := path + ".1"
	if err := os.Rename(path, oldPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("line 3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got = collect(t, tl.Lines(), 1)
	if texts(got)[0] != "line 3" {
		t.Fatalf("after rotation = %v", texts(got))
	}
	appendLines(t, oldPath, "stale line")
	appendLines(t, path, "line 4")
	got = collect(t, tl.Lines(), 1)
	if texts(got)[0] != "line 4" {
		t.Fatalf("after rotation, second line = %v", texts(got))
	}
	expectNoLines(t, tl.Lines(), 200*time.Millisecond)

	// Truncation: the file is cut back to zero, then new lines arrive.
	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	appendLines(t, path, "line 5")
	got = collect(t, tl.Lines(), 1)
	if texts(got)[0] != "line 5" {
		t.Fatalf("after truncation = %v", texts(got))
	}

	// Restart: the persisted offset must resume after line 5, so
	// nothing already read is delivered again.
	cancel()
	tl.Close()

	tl2, err := New([]config.Source{src}, stateDir, discardLogger())
	if err != nil {
		t.Fatalf("New (restart): %v", err)
	}
	tl2.PollInterval = 20 * time.Millisecond
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	tl2.Start(ctx2)
	expectNoLines(t, tl2.Lines(), 200*time.Millisecond)
	appendLines(t, path, "line 6")
	got = collect(t, tl2.Lines(), 1)
	if texts(got)[0] != "line 6" {
		t.Fatalf("after restart = %v", texts(got))
	}
	expectNoLines(t, tl2.Lines(), 200*time.Millisecond)
	cancel2()
	tl2.Close()
}

func TestTailerWaitsForMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "later.log")
	src := config.Source{Path: path, Format: "ssh"}

	tl, err := New([]config.Source{src}, filepath.Join(dir, "state"), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tl.PollInterval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	tl.Start(ctx)
	expectNoLines(t, tl.Lines(), 200*time.Millisecond)

	// The file appears later with existing content, then a new line.
	// The tailer starts at the end of the file it first sees, so give
	// it a poll cycle to observe the file before appending.
	if err := os.WriteFile(path, []byte("existing line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	appendLines(t, path, "new line")
	got := collect(t, tl.Lines(), 1)
	if texts(got)[0] != "new line" {
		t.Fatalf("after file appears = %v", texts(got))
	}
	cancel()
	tl.Close()
}

func TestTailerPartialLineHeldUntilNewline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "partial.log")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	tl, err := New([]config.Source{{Path: path, Format: "nginx"}}, filepath.Join(dir, "state"), discardLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tl.PollInterval = 20 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	tl.Start(ctx)

	// Give the tailer a poll cycle to observe the empty file before
	// writing, so the partial line is not skipped as old history.
	time.Sleep(100 * time.Millisecond)

	// A line without a trailing newline is not emitted yet.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("half a line"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	expectNoLines(t, tl.Lines(), 200*time.Millisecond)

	// Completing the line emits it whole, exactly once.
	appendLines(t, path, "")
	got := collect(t, tl.Lines(), 1)
	if texts(got)[0] != "half a line" {
		t.Fatalf("completed line = %v", texts(got))
	}
	expectNoLines(t, tl.Lines(), 200*time.Millisecond)
	cancel()
	tl.Close()
}
