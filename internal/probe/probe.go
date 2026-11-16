// Package probe checks internet reachability with tiny TCP handshakes and
// turns a stream of results into outage transitions.
package probe

import (
	"context"
	"net"
	"slices"
	"time"
)

// DefaultTargets are anycast DNS providers that accept TCP/443 everywhere.
var DefaultTargets = []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}

// Dial tries targets in order and reports success on the first completed
// handshake. Latency is the handshake time of that target.
func Dial(ctx context.Context, targets []string, timeout time.Duration) (bool, time.Duration) {
	d := net.Dialer{Timeout: timeout}
	for _, t := range targets {
		start := time.Now()
		c, err := d.DialContext(ctx, "tcp", t)
		if err != nil {
			continue
		}
		lat := time.Since(start)
		c.Close()
		return true, max(lat, time.Microsecond)
	}
	return false, 0
}

type Sample struct {
	T       time.Time
	OK      bool
	Latency time.Duration
}

// Uptime is the share of successful samples in percent.
func Uptime(s []Sample) float64 {
	if len(s) == 0 {
		return 100
	}
	ok := 0
	for _, x := range s {
		if x.OK {
			ok++
		}
	}
	return float64(ok) * 100 / float64(len(s))
}

// P95 is the nearest-rank 95th percentile latency over successful samples.
func P95(s []Sample) time.Duration {
	var l []time.Duration
	for _, x := range s {
		if x.OK {
			l = append(l, x.Latency)
		}
	}
	if len(l) == 0 {
		return 0
	}
	slices.Sort(l)
	return l[nearestRank(len(l), 0.95)]
}

func nearestRank(n int, p float64) int {
	r := int(float64(n)*p + 0.999999)
	return min(max(r, 1), n) - 1
}

type Outage struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (o Outage) Duration() time.Duration { return o.End.Sub(o.Start) }

type Transition struct {
	Online bool
	At     time.Time
	Outage *Outage // set when coming back online
}

// Detector is a small state machine: offline after Threshold consecutive
// failures (dated at the first failure), online again after one success.
type Detector struct {
	threshold int
	online    bool
	fails     int
	firstFail time.Time
	downSince time.Time
}

func NewDetector(threshold int) *Detector {
	return &Detector{threshold: max(threshold, 1), online: true}
}

func (d *Detector) Online() bool { return d.online }

// DownSince is the start of the current outage (zero when online).
func (d *Detector) DownSince() time.Time {
	if d.online {
		return time.Time{}
	}
	return d.downSince
}

func (d *Detector) Observe(t time.Time, ok bool) *Transition {
	if ok {
		d.fails = 0
		if d.online {
			return nil
		}
		d.online = true
		return &Transition{Online: true, At: t, Outage: &Outage{Start: d.downSince, End: t}}
	}
	if d.fails == 0 {
		d.firstFail = t
	}
	d.fails++
	if d.online && d.fails >= d.threshold {
		d.online = false
		d.downSince = d.firstFail
		return &Transition{Online: false, At: d.firstFail}
	}
	return nil
}
