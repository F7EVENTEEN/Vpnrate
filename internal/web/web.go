// Package web serves the local dashboard and its JSON API on loopback only.
package web

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/F7EVENTEEN/Vpnrate/internal/monitor"
	"github.com/F7EVENTEEN/Vpnrate/internal/store"
)

//go:embed dashboard.html
var dashboard []byte

type Provider interface {
	Status() monitor.Status
	Events(since time.Time) []store.Event
	Samples(hours int) []store.MinuteSample
	Profiles(days int) []monitor.ProfileStats
	Recheck()
	SetBrowserWebRTC(ips []string)
}

func ListenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

func Handler(p Provider) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'")
		w.Write(dashboard)
	})
	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, p.Status())
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, r *http.Request) {
		since := time.Now().Add(-7 * 24 * time.Hour)
		if s := r.URL.Query().Get("since"); s != "" {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				since = t
			}
		}
		ev := p.Events(since)
		if ev == nil {
			ev = []store.Event{}
		}
		writeJSON(w, ev)
	})
	mux.HandleFunc("GET /api/samples", func(w http.ResponseWriter, r *http.Request) {
		h, _ := strconv.Atoi(r.URL.Query().Get("hours"))
		h = min(max(h, 1), 24*30)
		s := p.Samples(h)
		if s == nil {
			s = []store.MinuteSample{}
		}
		writeJSON(w, s)
	})
	mux.HandleFunc("GET /api/profiles", func(w http.ResponseWriter, r *http.Request) {
		d, _ := strconv.Atoi(r.URL.Query().Get("days"))
		writeJSON(w, p.Profiles(min(max(d, 1), 30)))
	})
	mux.HandleFunc("POST /api/recheck", func(w http.ResponseWriter, r *http.Request) {
		p.Recheck()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/webrtc", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IPs []string `json:"ips"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		if body.IPs == nil {
			body.IPs = []string{}
		}
		p.SetBrowserWebRTC(body.IPs)
		w.WriteHeader(http.StatusNoContent)
	})
	return guard(mux)
}

// guard blocks DNS-rebinding (foreign Host header) and cross-site form
// posts: browsers cannot send application/json cross-origin without a
// CORS preflight, which we never approve.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost {
			mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if mt != "application/json" {
				http.Error(w, "json required", http.StatusUnsupportedMediaType)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
