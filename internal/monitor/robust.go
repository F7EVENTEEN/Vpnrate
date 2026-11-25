package monitor

import (
	"errors"
	"log"
	"runtime/debug"
	"time"
)

// Robustness: the agent must keep running through VPN switches, sleep and
// flaky drivers, and leave evidence when something does go wrong.

// depTimeout bounds OS calls that have no timeout of their own (adapter
// enumeration, registry). A call that overruns is abandoned, not awaited.
var depTimeout = 3 * time.Second

var errDepTimeout = errors.New("timed out")

func withTimeout[T any](fn func() (T, error)) (T, error) {
	type res struct {
		v   T
		err error
	}
	ch := make(chan res, 1)
	go func() {
		v, err := fn()
		ch <- res{v, err}
	}()
	select {
	case r := <-ch:
		return r.v, r.err
	case <-time.After(depTimeout):
		var zero T
		return zero, errDepTimeout
	}
}

// step runs one unit of monitor work and turns a panic into a log entry
// with a stack trace, so a bug in one check can't take the agent down.
func (m *Monitor) step(name string, fn func()) (ok bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("monitor: %s panicked: %v\n%s", name, r, debug.Stack())
			ok = false
		}
	}()
	fn()
	return true
}

// SinceBeat is how long ago the last connectivity tick completed; the
// watchdog uses it to detect a stuck monitor.
func (m *Monitor) SinceBeat() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.d.Now().Sub(m.beat)
}
