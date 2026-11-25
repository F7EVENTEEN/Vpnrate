package monitor

import (
	"context"
	"testing"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/netif"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
)

// While a VPN adapter is torn down, Windows' adapter enumeration can block.
// That must not freeze the monitor or fake a "VPN down".
func TestTickSurvivesHangingTunnelScan(t *testing.T) {
	f := newFake()
	m, evs := newMonitor(t, f)
	m.Tick(context.Background())

	old := depTimeout
	depTimeout = 100 * time.Millisecond
	defer func() { depTimeout = old }()
	block := make(chan struct{})
	defer close(block)
	m.d.Tunnels = func() ([]netif.Iface, error) { <-block; return nil, nil }

	done := make(chan struct{})
	go func() { m.Tick(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Tick hung on a blocked tunnel scan")
	}
	if !m.Status().VPNActive || has(*evs, store.KindVPNDown) {
		t.Fatalf("a timed-out scan must keep the last known tunnels: %v", kinds(*evs))
	}
}

func TestStepRecoversPanic(t *testing.T) {
	f := newFake()
	m, _ := newMonitor(t, f)
	m.d.Lookup = func(context.Context, string) (ipinfo.Info, error) { panic("boom") }
	if m.step("check_ip", func() { m.CheckIP(context.Background()) }) {
		t.Fatal("step must report the panic")
	}
	// The monitor keeps working afterwards.
	if !m.step("tick", func() { m.Tick(context.Background()) }) {
		t.Fatal("a normal step must succeed")
	}
}

func TestHeartbeat(t *testing.T) {
	f := newFake()
	m, _ := newMonitor(t, f)
	m.Tick(context.Background())
	if m.SinceBeat() != 0 {
		t.Fatalf("just ticked, since = %v", m.SinceBeat())
	}
	f.now = f.now.Add(3 * time.Minute)
	if m.SinceBeat() != 3*time.Minute {
		t.Fatalf("since = %v, want 3m", m.SinceBeat())
	}
	m.Tick(context.Background())
	if m.SinceBeat() != 0 {
		t.Fatal("a tick resets the heartbeat")
	}
}
