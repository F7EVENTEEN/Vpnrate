package publicip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func server(status int, body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
}

func TestFallbackToValidSource(t *testing.T) {
	bad := server(500, "oops")
	defer bad.Close()
	garbage := server(200, "<html>not an ip</html>")
	defer garbage.Close()
	good := server(200, "203.0.113.7\n")
	defer good.Close()

	f := &Fetcher{Client: bad.Client(), Sources: []string{bad.URL, garbage.URL, good.URL}, Want: V4}
	ip, err := f.Get(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "203.0.113.7" {
		t.Fatalf("ip = %s", ip)
	}
}

func TestAllSourcesBroken(t *testing.T) {
	bad := server(503, "")
	defer bad.Close()
	f := &Fetcher{Client: bad.Client(), Sources: []string{bad.URL, bad.URL}, Want: V4}
	if _, err := f.Get(context.Background()); err == nil {
		t.Fatal("want error")
	}
}

func TestFamilyValidation(t *testing.T) {
	v6 := server(200, "2001:db8::1")
	defer v6.Close()
	f := &Fetcher{Client: v6.Client(), Sources: []string{v6.URL}, Want: V4}
	if _, err := f.Get(context.Background()); err == nil {
		t.Fatal("v6 answer must be rejected when v4 is wanted")
	}
	f.Want = V6
	ip, err := f.Get(context.Background())
	if err != nil || ip.String() != "2001:db8::1" {
		t.Fatalf("want v6, got %v %v", ip, err)
	}
}

func TestPrivateAnswerRejected(t *testing.T) {
	s := server(200, "192.168.1.10")
	defer s.Close()
	f := &Fetcher{Client: s.Client(), Sources: []string{s.URL}, Want: V4}
	if _, err := f.Get(context.Background()); err == nil {
		t.Fatal("private address is not a public IP")
	}
}
