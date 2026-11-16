package probe

import (
	"context"
	"net"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func TestDetectorSingleFailureIsNotOutage(t *testing.T) {
	d := NewDetector(2)
	if tr := d.Observe(t0, true); tr != nil {
		t.Fatalf("first success should not transition from initial online state: %+v", tr)
	}
	if tr := d.Observe(t0.Add(5*time.Second), false); tr != nil {
		t.Fatalf("one failure must not open an outage: %+v", tr)
	}
	if !d.Online() {
		t.Fatal("still online after one failure")
	}
	if tr := d.Observe(t0.Add(10*time.Second), true); tr != nil {
		t.Fatalf("recovery after a blip must not emit: %+v", tr)
	}
}

func TestDetectorOutageLifecycle(t *testing.T) {
	d := NewDetector(2)
	d.Observe(t0, true)
	d.Observe(t0.Add(5*time.Second), false)
	tr := d.Observe(t0.Add(10*time.Second), false)
	if tr == nil || tr.Online {
		t.Fatalf("want offline transition, got %+v", tr)
	}
	if !tr.At.Equal(t0.Add(5 * time.Second)) {
		t.Fatalf("outage must start at first failure, got %v", tr.At)
	}
	if d.Online() {
		t.Fatal("detector should be offline")
	}
	d.Observe(t0.Add(15*time.Second), false)
	tr = d.Observe(t0.Add(20*time.Second), true)
	if tr == nil || !tr.Online || tr.Outage == nil {
		t.Fatalf("want online transition with outage, got %+v", tr)
	}
	if tr.Outage.Duration() != 15*time.Second {
		t.Fatalf("outage duration = %v, want 15s", tr.Outage.Duration())
	}
}

func TestUptimeAndP95(t *testing.T) {
	var s []Sample
	for i := 0; i < 100; i++ {
		s = append(s, Sample{T: t0.Add(time.Duration(i) * time.Second), OK: i != 7, Latency: time.Duration(i+1) * time.Millisecond})
	}
	if got := Uptime(s); got != 99 {
		t.Fatalf("uptime = %v, want 99", got)
	}
	if got := P95(s); got != 96*time.Millisecond {
		t.Fatalf("p95 = %v, want 96ms", got)
	}
	if Uptime(nil) != 100 || P95(nil) != 0 {
		t.Fatal("empty input should be 100% uptime and zero p95")
	}
}

func TestDialProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// Reserve a port and close it so that dialing it fails fast.
	dead, _ := net.Listen("tcp", "127.0.0.1:0")
	deadAddr := dead.Addr().String()
	dead.Close()

	ok, lat := Dial(context.Background(), []string{deadAddr, ln.Addr().String()}, time.Second)
	if !ok || lat <= 0 {
		t.Fatalf("want success via second target, got ok=%v lat=%v", ok, lat)
	}
	ok, _ = Dial(context.Background(), []string{deadAddr}, 500*time.Millisecond)
	if ok {
		t.Fatal("want failure when every target is dead")
	}
}
