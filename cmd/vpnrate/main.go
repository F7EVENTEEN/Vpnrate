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
	"os/signal"
	"path/filepath"
	"runtime/debug"
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
	Notifications bool `json:"notifications"`
	AutostartSet  bool `json:"autostart_set"` // first-run autostart decision was made
}

func main() {
	headless := flag.Bool("headless", false, "run without tray icon (logs to stdout)")
	port := flag.Int("port", 8737, "dashboard port on 127.0.0.1")
	dataDir := flag.String("data", defaultDataDir(), "where history is stored")
	noAutostart := flag.Bool("no-autostart", false, "do not register autostart on first run")
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
		}
	}
	dashURL := fmt.Sprintf("http://127.0.0.1:%d/", *port)

	ln, err := web.ListenLoopback(*port)
	if err != nil {
		// Most likely another instance is already running: just show it.
		log.Printf("listen: %v", err)
		if !*headless {
			ui.OpenURL(dashURL)
		}
		os.Exit(1)
	}

	cfgPath := filepath.Join(*dataDir, "config.json")
	cfg := loadConfig(cfgPath)
	if !cfg.AutostartSet && !*headless {
		if !*noAutostart {
			if err := ui.SetAutostart(true); err != nil {
				log.Printf("autostart: %v", err)
			}
		}
		cfg.AutostartSet = true
		saveConfig(cfgPath, cfg)
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
	log.Printf("vpnrate %s: dashboard at %s, data in %s", version, dashURL, *dataDir)

	if *headless {
		mon.Subscribe(func(e store.Event) { log.Printf("[%s] %s", e.Kind, e.Message) })
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
	} else {
		tray := &ui.Tray{Mon: mon, URL: dashURL, Notify: cfg.Notifications}
		tray.Run()
		cfg.Notifications = tray.Notify
		saveConfig(cfgPath, cfg)
	}
	cancel()
	sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer scancel()
	srv.Shutdown(sctx)
	time.Sleep(100 * time.Millisecond) // let the monitor flush the current minute
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
