package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func TestEventsRoundTripAndSince(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if err := s.AppendEvent(Event{Time: t0.Add(time.Duration(i) * time.Hour), Kind: KindOffline, Message: "down"}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.Events(time.Time{})
	if err != nil || len(all) != 5 {
		t.Fatalf("want 5 events, got %d (%v)", len(all), err)
	}
	recent, _ := s.Events(t0.Add(3 * time.Hour))
	if len(recent) != 2 {
		t.Fatalf("want 2 events since +3h, got %d", len(recent))
	}
	if recent[0].Kind != KindOffline || recent[0].Message != "down" {
		t.Fatalf("event fields lost: %+v", recent[0])
	}
}

func TestSamplesAcrossDays(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.AppendSample(MinuteSample{T: t0.Add(-24 * time.Hour), Probes: 12, OK: 12, AvgMs: 30, P95Ms: 40})
	s.AppendSample(MinuteSample{T: t0, Probes: 12, OK: 10, AvgMs: 50, P95Ms: 90})
	got, err := s.Samples(t0.Add(-time.Hour))
	if err != nil || len(got) != 1 || got[0].OK != 10 {
		t.Fatalf("want only today's sample, got %+v (%v)", got, err)
	}
	got, _ = s.Samples(t0.Add(-48 * time.Hour))
	if len(got) != 2 {
		t.Fatalf("want both samples, got %d", len(got))
	}
	files, _ := filepath.Glob(filepath.Join(dir, "samples-*.jsonl"))
	if len(files) != 2 {
		t.Fatalf("want one file per day, got %v", files)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	old := t0.Add(-40 * 24 * time.Hour)
	s.AppendSample(MinuteSample{T: old, Probes: 1, OK: 1})
	s.AppendSample(MinuteSample{T: t0, Probes: 1, OK: 1})
	s.AppendEvent(Event{Time: old, Kind: KindIPChanged})
	s.AppendEvent(Event{Time: t0, Kind: KindIPChanged})

	if err := s.Prune(t0, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "samples-"+old.Format("2006-01-02")+".jsonl")); !os.IsNotExist(err) {
		t.Fatal("old sample file must be deleted")
	}
	ev, _ := s.Events(time.Time{})
	if len(ev) != 1 || !ev[0].Time.Equal(t0) {
		t.Fatalf("old events must be dropped, got %+v", ev)
	}
}

func TestCorruptLineSkipped(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	s.AppendEvent(Event{Time: t0, Kind: KindOnline})
	f, _ := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("{broken\n")
	f.Close()
	s.AppendEvent(Event{Time: t0.Add(time.Minute), Kind: KindOnline})
	ev, err := s.Events(time.Time{})
	if err != nil || len(ev) != 2 {
		t.Fatalf("corrupt line must be skipped, got %d (%v)", len(ev), err)
	}
}
