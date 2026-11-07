// Package tailer follows log files and emits new lines on a channel.
// Each configured source runs in its own goroutine. Rotation (inode
// change) and truncation (file smaller than the read offset) are
// followed, a missing file is waited on instead of crashing the agent,
// and the read offset of every file is persisted so a restart resumes
// where the previous run stopped instead of re-reading the file.
package tailer

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"logbanner/internal/config"
)

// Line is one raw log line read from a source.
type Line struct {
	Source string
	Format string
	Text   string
}

// offsetState is the persisted read position of one source file.
type offsetState struct {
	inode     uint64
	offset    int64
	lastWrite time.Time
}

// persistedOffset is the JSON form of offsetState on disk. The path is
// stored so a state file is never applied to a different source.
type persistedOffset struct {
	Path   string `json:"path"`
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

// Tailer follows the configured sources. PollInterval controls how
// often a file is checked for new data; the default is one second.
// It is a tuning knob, and tests set it much lower.
type Tailer struct {
	sources      []config.Source
	stateDir     string
	logger       *slog.Logger
	PollInterval time.Duration

	out     chan Line
	wg      sync.WaitGroup
	mu      sync.Mutex
	offsets map[string]*offsetState
}

// New creates a Tailer. It creates stateDir when missing; no log file
// is opened here, so a missing source file is not an error.
func New(sources []config.Source, stateDir string, logger *slog.Logger) (*Tailer, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if stateDir == "" {
		stateDir = "var"
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("create state dir %s: %w", stateDir, err)
	}
	return &Tailer{
		sources:      sources,
		stateDir:     stateDir,
		logger:       logger,
		PollInterval: time.Second,
		out:          make(chan Line, 1000),
		offsets:      map[string]*offsetState{},
	}, nil
}

// Start launches one goroutine per source. The goroutines stop when
// ctx is done; call Close afterwards to persist final offsets.
func (t *Tailer) Start(ctx context.Context) {
	for _, src := range t.sources {
		t.wg.Add(1)
		go t.follow(ctx, src)
	}
}

// Lines returns the channel new lines arrive on.
func (t *Tailer) Lines() <-chan Line {
	return t.out
}

// Close waits for the follow goroutines to exit, persists every
// offset, and closes the Lines channel. Call it after the context
// passed to Start is done.
func (t *Tailer) Close() {
	t.wg.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	for path, st := range t.offsets {
		if err := t.writeOffsetLocked(path, st); err != nil {
			t.logger.Error("failed to persist offset", "path", path, "error", err)
		}
	}
	close(t.out)
}

// sleep waits one poll interval, returning false when ctx ends first.
func (t *Tailer) sleep(ctx context.Context) bool {
	timer := time.NewTimer(t.PollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// stateFile returns the state file for a source path. The name is a
// hash of the path, so any path maps to a safe file name.
func (t *Tailer) stateFile(sourcePath string) string {
	sum := sha256.Sum256([]byte(sourcePath))
	return filepath.Join(t.stateDir, hex.EncodeToString(sum[:])[:16]+".offset")
}

// loadOffset reads a persisted offset. It returns false when there is
// no usable state: no state file, a corrupt one, a state for another
// path, or a state for a different inode (the file was rotated while
// the agent was down).
func (t *Tailer) loadOffset(statePath, sourcePath string, inode uint64) (int64, bool) {
	data, err := os.ReadFile(statePath)
	if err != nil {
		return 0, false
	}
	var st persistedOffset
	if err := json.Unmarshal(data, &st); err != nil {
		return 0, false
	}
	if st.Path != sourcePath || st.Inode != inode || st.Offset < 0 {
		return 0, false
	}
	return st.Offset, true
}

// writeOffsetLocked writes one offset atomically (temp file plus
// rename) so a crash mid-write never leaves a half-written state.
func (t *Tailer) writeOffsetLocked(path string, st *offsetState) error {
	data, err := json.Marshal(persistedOffset{Path: path, Inode: st.inode, Offset: st.offset})
	if err != nil {
		return err
	}
	tmp := t.stateFile(path) + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, t.stateFile(path))
}

// recordOffset remembers a new read position and persists it at most
// once a second per file; Close persists the final position.
func (t *Tailer) recordOffset(path string, inode uint64, offset int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st, ok := t.offsets[path]
	if !ok {
		st = &offsetState{}
		t.offsets[path] = st
	}
	st.inode = inode
	st.offset = offset
	if time.Since(st.lastWrite) < time.Second {
		return
	}
	st.lastWrite = time.Now()
	if err := t.writeOffsetLocked(path, st); err != nil {
		t.logger.Error("failed to persist offset", "path", path, "error", err)
	}
}

// fileID returns the inode and size of a file. The inode is 0 on
// platforms without stat_t, where rotation detection cannot work.
func fileID(info os.FileInfo) (uint64, int64) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return st.Ino, info.Size()
	}
	return 0, info.Size()
}

// follow tails one source file until ctx ends.
func (t *Tailer) follow(ctx context.Context, src config.Source) {
	defer t.wg.Done()
	statePath := t.stateFile(src.Path)

	var (
		f             *os.File
		reader        *bufio.Reader
		inode         uint64
		offset        int64
		pending       string // a partial line with no newline yet
		warnedMissing bool
	)

	for {
		select {
		case <-ctx.Done():
			if f != nil {
				f.Close()
			}
			return
		default:
		}

		info, err := os.Stat(src.Path)
		if err != nil {
			if os.IsNotExist(err) {
				if !warnedMissing {
					t.logger.Warn("log source missing, waiting for it to appear", "path", src.Path)
					warnedMissing = true
				}
			} else {
				t.logger.Error("cannot stat log source", "path", src.Path, "error", err)
			}
			if !t.sleep(ctx) {
				return
			}
			continue
		}
		warnedMissing = false
		curInode, curSize := fileID(info)

		if f == nil {
			f, err = os.Open(src.Path)
			if err != nil {
				t.logger.Error("cannot open log source", "path", src.Path, "error", err)
				if !t.sleep(ctx) {
					return
				}
				continue
			}
			inode = curInode
			if off, ok := t.loadOffset(statePath, src.Path, curInode); ok {
				offset = off
			} else if _, statErr := os.Stat(statePath); statErr == nil {
				// State exists but for another inode: the file was
				// rotated while the agent was down, so read the new
				// file from the start instead of skipping it.
				offset = 0
			} else {
				// First run for this source: start at the end so
				// old log history is not replayed as new events.
				offset = curSize
			}
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				t.logger.Error("cannot seek log source", "path", src.Path, "error", err)
				f.Close()
				f = nil
				if !t.sleep(ctx) {
					return
				}
				continue
			}
			reader = nil
		} else if curInode != inode {
			t.logger.Info("log source rotated", "path", src.Path)
			f.Close()
			f, err = os.Open(src.Path)
			if err != nil {
				t.logger.Error("cannot open rotated log source", "path", src.Path, "error", err)
				if !t.sleep(ctx) {
					return
				}
				continue
			}
			inode = curInode
			offset = 0
			pending = ""
			reader = nil
			t.recordOffset(src.Path, inode, 0)
		} else if curSize < offset {
			t.logger.Info("log source truncated", "path", src.Path)
			offset = 0
			pending = ""
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				t.logger.Error("cannot seek truncated log source", "path", src.Path, "error", err)
				if !t.sleep(ctx) {
					return
				}
				continue
			}
			reader = nil
			t.recordOffset(src.Path, inode, 0)
		}

		if reader == nil {
			reader = bufio.NewReader(f)
		}
		for {
			chunk, err := reader.ReadString('\n')
			if len(chunk) > 0 {
				pending += chunk
				if strings.HasSuffix(chunk, "\n") {
					line := strings.TrimSuffix(pending, "\n")
					line = strings.TrimSuffix(line, "\r")
					offset += int64(len(pending))
					pending = ""
					t.recordOffset(src.Path, inode, offset)
					select {
					case t.out <- Line{Source: src.Path, Format: src.Format, Text: line}:
					case <-ctx.Done():
						f.Close()
						return
					}
				}
			}
			if err != nil {
				if err != io.EOF {
					t.logger.Error("error reading log source", "path", src.Path, "error", err)
				}
				break
			}
		}

		if !t.sleep(ctx) {
			f.Close()
			return
		}
	}
}
