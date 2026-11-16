// Package store keeps history as append-only JSON Lines files: one events
// file and one samples file per day. No database, nothing leaves the disk.
package store

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	KindOffline   = "offline"
	KindOnline    = "online"
	KindIPChanged = "ip_changed"
	KindVPNDown   = "vpn_down"
	KindVPNUp     = "vpn_up"
	KindLeak      = "leak"
	KindLeakFixed = "leak_fixed"
	KindStarted   = "started"
)

type Event struct {
	Time    time.Time      `json:"time"`
	Kind    string         `json:"kind"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

// MinuteSample aggregates the connectivity probes of one minute.
type MinuteSample struct {
	T      time.Time `json:"t"`
	Probes int       `json:"probes"`
	OK     int       `json:"ok"`
	AvgMs  float64   `json:"avg_ms"`
	P95Ms  float64   `json:"p95_ms"`
	// Profile is the exit network the minute was spent on (e.g. "AS14061-NL").
	Profile string `json:"profile,omitempty"`
}

type Store struct {
	dir string
	mu  sync.Mutex
}

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) eventsPath() string { return filepath.Join(s.dir, "events.jsonl") }

func (s *Store) samplesPath(t time.Time) string {
	return filepath.Join(s.dir, "samples-"+t.UTC().Format("2006-01-02")+".jsonl")
}

func (s *Store) AppendEvent(e Event) error { return s.appendLine(s.eventsPath(), e) }

func (s *Store) AppendSample(m MinuteSample) error { return s.appendLine(s.samplesPath(m.T), m) }

func (s *Store) appendLine(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func (s *Store) Events(since time.Time) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	err := readLines(s.eventsPath(), func(e Event) {
		if !e.Time.Before(since) {
			out = append(out, e)
		}
	})
	return out, err
}

func (s *Store) Samples(since time.Time) ([]MinuteSample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	files, _ := filepath.Glob(filepath.Join(s.dir, "samples-*.jsonl"))
	var out []MinuteSample
	day := since.UTC().Format("2006-01-02")
	for _, f := range files { // Glob returns lexical = chronological order
		if d := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "samples-"), ".jsonl"); d < day {
			continue
		}
		if err := readLines(f, func(m MinuteSample) {
			if !m.T.Before(since) {
				out = append(out, m)
			}
		}); err != nil {
			return out, err
		}
	}
	return out, nil
}

// Prune deletes sample files and events older than keep.
func (s *Store) Prune(now time.Time, keep time.Duration) error {
	cutoff := now.Add(-keep)
	s.mu.Lock()
	defer s.mu.Unlock()
	files, _ := filepath.Glob(filepath.Join(s.dir, "samples-*.jsonl"))
	day := cutoff.UTC().Format("2006-01-02")
	for _, f := range files {
		if d := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "samples-"), ".jsonl"); d < day {
			os.Remove(f)
		}
	}
	var keepEv []Event
	if err := readLines(s.eventsPath(), func(e Event) {
		if !e.Time.Before(cutoff) {
			keepEv = append(keepEv, e)
		}
	}); err != nil {
		return err
	}
	tmp := s.eventsPath() + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range keepEv {
		enc.Encode(e)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, s.eventsPath())
}

// SaveJSON atomically writes v to name inside the data directory.
func (s *Store) SaveJSON(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, name)
	if err := os.WriteFile(path+".tmp", b, 0o644); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (s *Store) LoadJSON(name string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := os.ReadFile(filepath.Join(s.dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func readLines[T any](path string, fn func(T)) error {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			fn(v)
		}
	}
	return sc.Err()
}
