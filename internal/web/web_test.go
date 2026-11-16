package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/monitor"
	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/store"
)

type fakeProvider struct {
	rechecked bool
	webrtc    []string
}

func (f *fakeProvider) Status() monitor.Status {
	return monitor.Status{Online: true, PublicV4: "203.0.113.9"}
}
func (f *fakeProvider) Events(since time.Time) []store.Event {
	return []store.Event{{Kind: store.KindOnline, Time: time.Now()}}
}
func (f *fakeProvider) Samples(hours int) []store.MinuteSample { return nil }
func (f *fakeProvider) Recheck()                               { f.rechecked = true }
func (f *fakeProvider) SetBrowserWebRTC(ips []string)          { f.webrtc = ips }

func do(h http.Handler, method, path, host, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = host
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestStatus(t *testing.T) {
	h := Handler(&fakeProvider{})
	w := do(h, "GET", "/api/status", "127.0.0.1:8737", "")
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	var st map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st["public_v4"] != "203.0.113.9" || st["online"] != true {
		t.Fatalf("unexpected status json: %v", st)
	}
	for _, k := range []string{"trust", "stability", "leaks"} {
		if _, ok := st[k]; !ok {
			t.Fatalf("missing %q in %v", k, st)
		}
	}
}

func TestDashboardServed(t *testing.T) {
	w := do(Handler(&fakeProvider{}), "GET", "/", "localhost:8737", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "<html") {
		t.Fatalf("dashboard not served: %d", w.Code)
	}
}

func TestWebRTCAndRecheck(t *testing.T) {
	p := &fakeProvider{}
	h := Handler(p)
	w := do(h, "POST", "/api/webrtc", "127.0.0.1:8737", `{"ips":["192.168.0.2","95.167.1.1"]}`)
	if w.Code != 204 || len(p.webrtc) != 2 {
		t.Fatalf("webrtc not accepted: %d %v", w.Code, p.webrtc)
	}
	w = do(h, "POST", "/api/recheck", "127.0.0.1:8737", `{}`)
	if w.Code != 204 || !p.rechecked {
		t.Fatalf("recheck not triggered: %d", w.Code)
	}
}

func TestRejectsForeignHost(t *testing.T) {
	h := Handler(&fakeProvider{})
	if w := do(h, "GET", "/api/status", "evil.example:8737", ""); w.Code != http.StatusForbidden {
		t.Fatalf("dns-rebinding host must be rejected, got %d", w.Code)
	}
}

func TestPostRequiresJSON(t *testing.T) {
	p := &fakeProvider{}
	r := httptest.NewRequest("POST", "/api/recheck", strings.NewReader("x=1"))
	r.Host = "127.0.0.1:8737"
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	Handler(p).ServeHTTP(w, r)
	if w.Code != http.StatusUnsupportedMediaType || p.rechecked {
		t.Fatalf("form post from another site must be refused, got %d", w.Code)
	}
}

func TestListenLoopback(t *testing.T) {
	ln, err := ListenLoopback(0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if !strings.HasPrefix(ln.Addr().String(), "127.0.0.1:") {
		t.Fatalf("must bind loopback only, got %s", ln.Addr())
	}
}
