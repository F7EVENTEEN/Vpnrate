// Command vpnrate is a lightweight background agent that watches your
// internet connection and rates how stable and how "clean" it is.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
	_ "time/tzdata" // timezone database for the leak check on machines without one

	"github.com/F7EVENTEEN/Vpnrate/internal/ipinfo"
	"github.com/F7EVENTEEN/Vpnrate/internal/leak"
	"github.com/F7EVENTEEN/Vpnrate/internal/monitor"
	"github.com/F7EVENTEEN/Vpnrate/internal/netif"
	"github.com/F7EVENTEEN/Vpnrate/internal/probe"
	"github.com/F7EVENTEEN/Vpnrate/internal/publicip"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
	"github.com/F7EVENTEEN/Vpnrate/internal/sysproxy"
	"github.com/F7EVENTEEN/Vpnrate/internal/ui"
	"github.com/F7EVENTEEN/Vpnrate/internal/web"
)

var version = "dev"

type config struct {
	Notifications bool   `json:"notifications"`
	Autostart     *bool  `json:"autostart,omitempty"`      // nil means on (the default)
	AutostartPath string `json:"autostart_path,omitempty"` // exe we registered
}

func (c config) wantAutostart() bool { return c.Autostart == nil || *c.Autostart }

func main() {
	headless := flag.Bool("headless", false, "run without tray icon (logs to stdout)")
	port := flag.Int("port", 8737, "dashboard port on 127.0.0.1")
	dataDir := flag.String("data", defaultDataDir(), "where history is stored")
	noAutostart := flag.Bool("no-autostart", false, "don't touch autostart during this run")
	autostarted := flag.Bool("autostart", false, "set by the autostart entry; exit quietly if already running")
	restarted := flag.Bool("restarted", false, "set by the watchdog when it restarts the agent")
	showVersion := flag.Bool("version", false, "print version")
	demo := flag.Bool("demo", false, "serve the dashboard with fake data (no network access)")
	flag.Parse()
	// Stay small: collect more eagerly and hand memory back to the OS.
	debug.SetGCPercent(50)
	debug.SetMemoryLimit(24 << 20)
	if *showVersion {
		fmt.Println("vpnrate", version)
		return
	}
	if *demo {
		runDemo(*port)
		return
	}

	st, err := store.Open(*dataDir)
	if err != nil {
		log.Fatal(err)
	}
	if !*headless {
		if f, err := os.OpenFile(filepath.Join(*dataDir, "vpnrate.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
			log.SetOutput(f)
			// The tray build has no console: send panics and fatal errors
			// to the log instead of losing them.
			debug.SetCrashOutput(f, debug.CrashOptions{})
		}
	}
	dashURL := fmt.Sprintf("http://127.0.0.1:%d/", *port)

	ln, err := web.ListenLoopback(*port)
	for i := 0; err != nil && *restarted && i < 30; i++ {
		time.Sleep(500 * time.Millisecond) // the old instance is still exiting
		ln, err = web.ListenLoopback(*port)
	}
	if err != nil {
		// Most likely another instance is already running: just show it.
		// When the user double-clicks the exe, show the running instance;
		// a duplicate launched at logon just leaves.
		log.Printf("listen: %v", err)
		if !*headless && !*autostarted {
			ui.OpenURL(dashURL)
		}
		os.Exit(1)
	}

	cfgPath := filepath.Join(*dataDir, "config.json")
	cfg := loadConfig(cfgPath)
	var cfgMu sync.Mutex
	if !*headless && !*noAutostart {
		syncAutostart(&cfg)
		saveConfig(cfgPath, cfg)
		// Re-check periodically: an entry removed while we run is repaired
		// long before the next reboot, and the log shows when it vanished.
		go func() {
			for range time.Tick(10 * time.Minute) {
				cfgMu.Lock()
				syncAutostart(&cfg)
				saveConfig(cfgPath, cfg)
				cfgMu.Unlock()
			}
		}()
	}

	// Proxy-mode VPN clients set the system proxy instead of adding a tunnel
	// adapter; route our checks the same way so we see the browser's exit.
	proxyURL := func() *url.URL {
		if p, ok := sysproxy.Current(); ok {
			return p.URL()
		}
		return nil
	}
	ipc := ipinfo.NewClient(filepath.Join(*dataDir, "ipcache.json"), func(*http.Request) (*url.URL, error) { return proxyURL(), nil })
	v4, v6 := publicip.New(publicip.V4, proxyURL), publicip.New(publicip.V6, proxyURL)
	mon := monitor.New(monitor.Deps{
		Probe: func(ctx context.Context) (bool, time.Duration) {
			if p, ok := sysproxy.Current(); ok {
				return probeVia(ctx, p)
			}
			return probe.Dial(ctx, probe.DefaultTargets, 3*time.Second)
		},
		Proxy: func() string {
			if p, ok := sysproxy.Current(); ok {
				return p.Addr
			}
			return ""
		},
		PublicV4:    v4.Get,
		PublicV6:    v6.Get,
		Lookup:      ipc.Lookup,
		STUN:        func(ctx context.Context) (netip.Addr, error) { return leak.UDPExitIP(ctx, leak.DefaultSTUNServers) },
		DNSResolver: func(ctx context.Context) (netip.Addr, error) { return leak.ResolverIP(ctx, nil) },
		Tunnels:     netif.Tunnels,
	}, st)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &http.Server{Handler: web.Handler(mon), ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	go mon.Run(ctx)
	go watchdog(mon)
	log.Printf("vpnrate %s: dashboard at %s, data in %s", version, dashURL, *dataDir)

	if *headless {
		mon.Subscribe(func(e store.Event) { log.Printf("[%s] %s", e.Kind, e.Message) })
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
	} else {
		tray := &ui.Tray{Mon: mon, URL: dashURL, Notify: cfg.Notifications, Autostart: cfg.wantAutostart(),
			SetAutostart: func(on bool) error {
				cfgMu.Lock()
				defer cfgMu.Unlock()
				cfg.Autostart = &on
				syncAutostart(&cfg)
				saveConfig(cfgPath, cfg)
				return nil
			}}
		tray.Run()
		cfgMu.Lock()
		cfg.Notifications = tray.Notify
		saveConfig(cfgPath, cfg)
		cfgMu.Unlock()
	}
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	srv.Shutdown(sctx)
	time.Sleep(100 * time.Millisecond) // let the monitor flush the current minute
}

// syncAutostart makes the autostart entry match the preference and point at
// this exe. Running it on every launch repairs a deleted entry or a moved exe.
func syncAutostart(cfg *config) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	register, unregister := ui.PlanAutostart(ui.AutostartState{
		Want: cfg.wantAutostart(), Registered: ui.AutostartRegistered(),
		RegisteredPath: cfg.AutostartPath, Exe: exe,
	})
	switch {
	case register:
		task, run := ui.AutostartStatus()
		log.Printf("autostart: entry missing or stale (task=%v run=%v, registered for %q), repairing", task, run, cfg.AutostartPath)
		how, err := ui.EnableAutostart(exe)
		if err != nil {
			log.Printf("autostart: %v", err)
			return
		}
		cfg.AutostartPath = exe
		log.Printf("autostart registered (%s): %s", how, exe)
	case unregister:
		if err := ui.DisableAutostart(); err != nil {
			log.Printf("autostart: %v", err)
		}
		cfg.AutostartPath = ""
	}
}

func defaultDataDir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "vpnrate")
	}
	return "vpnrate-data"
}

func loadConfig(path string) config {
	cfg := config{Notifications: true}
	if b, err := os.ReadFile(path); err == nil {
		json.Unmarshal(b, &cfg)
	}
	return cfg
}

func saveConfig(path string, c config) {
	b, _ := json.MarshalIndent(c, "", "  ")
	os.WriteFile(path, b, 0o644)
}

// probeVia measures reachability through the proxy, which is what matters
// to the user: a dead proxy client means no internet for the browser.
func probeVia(ctx context.Context, p sysproxy.Proxy) (bool, time.Duration) {
	for _, t := range probe.DefaultTargets {
		start := time.Now()
		c, err := sysproxy.Dial(ctx, p, t, 4*time.Second)
		if err != nil {
			continue
		}
		c.Close()
		return true, time.Since(start)
	}
	return false, 0
}

// watchdog restarts the agent if the monitor loop stops completing ticks,
// after writing every goroutine's stack to the log so the cause can be
// found. A wall-clock jump means the PC was asleep, which is not a hang.
func watchdog(mon *monitor.Monitor) {
	last := time.Now().Round(0)
	for range time.Tick(30 * time.Second) {
		now := time.Now().Round(0)
		slept := now.Sub(last) > 90*time.Second
		last = now
		if slept {
			continue
		}
		if d := mon.SinceBeat(); d > 2*time.Minute {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			log.Printf("watchdog: monitor stuck for %s, restarting\n%s", d.Round(time.Second), buf[:n])
			restartSelf()
		}
	}
}

// restartSelf launches a fresh copy with the same flags and exits.
func restartSelf() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	args := []string{"-autostart", "-restarted"}
	for _, a := range os.Args[1:] {
		if a != "-autostart" && a != "-restarted" {
			args = append(args, a)
		}
	}
	if err := exec.Command(exe, args...).Start(); err != nil {
		log.Printf("watchdog: restart failed: %v", err)
		return
	}
	os.Exit(3)
}
