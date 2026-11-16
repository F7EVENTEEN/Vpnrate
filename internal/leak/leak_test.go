package leak

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/F7EVENTEEN/Vpn_rate_agent/internal/ipinfo"
)

var txid = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}

func TestBuildBindingRequest(t *testing.T) {
	b := BuildBindingRequest(txid)
	if len(b) != 20 {
		t.Fatalf("len = %d, want 20", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != 0x0001 || binary.BigEndian.Uint16(b[2:4]) != 0 {
		t.Fatal("wrong type/length")
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagic {
		t.Fatal("wrong magic cookie")
	}
	if !bytes.Equal(b[8:20], txid[:]) {
		t.Fatal("wrong transaction id")
	}
}

// fakeResponse builds a Binding Success Response with XOR-MAPPED-ADDRESS.
func fakeResponse(id [12]byte, ap netip.AddrPort) []byte {
	addr := ap.Addr()
	var attr []byte
	port := ap.Port() ^ uint16(stunMagic>>16)
	if addr.Is4() {
		attr = make([]byte, 8)
		attr[1] = 0x01
		binary.BigEndian.PutUint16(attr[2:4], port)
		a := addr.As4()
		var m [4]byte
		binary.BigEndian.PutUint32(m[:], stunMagic)
		for i := range a {
			attr[4+i] = a[i] ^ m[i]
		}
	} else {
		attr = make([]byte, 20)
		attr[1] = 0x02
		binary.BigEndian.PutUint16(attr[2:4], port)
		a := addr.As16()
		var key [16]byte
		binary.BigEndian.PutUint32(key[0:4], stunMagic)
		copy(key[4:], id[:])
		for i := range a {
			attr[4+i] = a[i] ^ key[i]
		}
	}
	msg := make([]byte, 20, 20+4+len(attr))
	binary.BigEndian.PutUint16(msg[0:2], 0x0101)
	binary.BigEndian.PutUint16(msg[2:4], uint16(4+len(attr)))
	binary.BigEndian.PutUint32(msg[4:8], stunMagic)
	copy(msg[8:20], id[:])
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], attrXorMappedAddress)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(attr)))
	return append(append(msg, hdr...), attr...)
}

func TestParseBindingResponse(t *testing.T) {
	for _, s := range []string{"203.0.113.5:54321", "[2001:db8::42]:3478"} {
		want := netip.MustParseAddrPort(s)
		got, err := ParseBindingResponse(fakeResponse(txid, want), txid)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got != want {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	other := [12]byte{9}
	if _, err := ParseBindingResponse(fakeResponse(other, netip.MustParseAddrPort("1.2.3.4:5")), txid); err == nil {
		t.Fatal("mismatched transaction id must be rejected")
	}
	if _, err := ParseBindingResponse([]byte{1, 2, 3}, txid); err == nil {
		t.Fatal("short packet must be rejected")
	}
}

func TestSTUNQueryAgainstFakeServer(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	mapped := netip.MustParseAddrPort("198.51.100.77:40000")
	go func() {
		buf := make([]byte, 1500)
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n < 20 {
			return
		}
		var id [12]byte
		copy(id[:], buf[8:20])
		pc.WriteTo(fakeResponse(id, mapped), from)
	}()
	got, err := STUNQuery(context.Background(), pc.LocalAddr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got != mapped {
		t.Fatalf("got %v, want %v", got, mapped)
	}
}

func TestJudgeDNS(t *testing.T) {
	exit := ipinfo.Info{IP: "203.0.113.9", Country: "NL", ASN: 14061}
	if v := JudgeDNS(exit, ipinfo.Info{IP: "172.68.1.1", Country: "NL", ASN: 13335}); v.Status != OK {
		t.Fatalf("same country resolver is fine: %+v", v)
	}
	if v := JudgeDNS(exit, ipinfo.Info{IP: "95.167.1.1", Country: "RU", ASN: 12389}); v.Status != Leak {
		t.Fatalf("resolver in another country is a leak: %+v", v)
	}
	// Seen live: sing-box exit in Zurich, Google DNS answering from Frankfurt.
	if v := JudgeDNS(ipinfo.Info{Country: "CH", ASN: 57043}, ipinfo.Info{IP: "172.217.33.215", Country: "DE", ASN: 15169, Org: "Google LLC"}); v.Status != OK {
		t.Fatalf("public anycast DNS in a neighbouring country is not a leak: %+v", v)
	}
	if v := JudgeDNS(exit, ipinfo.Info{IP: "77.88.8.8", Country: "RU", ASN: 13238, Org: "Yandex"}); v.Status != Leak {
		t.Fatalf("resolver in an unsupported country is a leak even if public: %+v", v)
	}
	if v := JudgeDNS(exit, ipinfo.Info{}); v.Status != Unknown {
		t.Fatalf("unknown resolver is unknown: %+v", v)
	}
}

func TestJudgeUDP(t *testing.T) {
	a := netip.MustParseAddr("203.0.113.9")
	b := netip.MustParseAddr("95.167.1.1")
	if JudgeUDP(a, a).Status != OK {
		t.Fatal("same ip is ok")
	}
	if JudgeUDP(a, b).Status != Leak {
		t.Fatal("different ip is a leak")
	}
	if JudgeUDP(a, netip.Addr{}).Status != Unknown {
		t.Fatal("missing stun result is unknown")
	}
}

func TestJudgeIPv6(t *testing.T) {
	v4 := &ipinfo.Info{Country: "NL", ASN: 14061}
	if JudgeIPv6(v4, nil).Status != OK {
		t.Fatal("no ipv6 means nothing leaks")
	}
	if JudgeIPv6(v4, &ipinfo.Info{Country: "NL", ASN: 14061}).Status != OK {
		t.Fatal("ipv6 through the same provider is fine")
	}
	if JudgeIPv6(v4, &ipinfo.Info{Country: "RU", ASN: 8359}).Status != Leak {
		t.Fatal("ipv6 via home isp is a leak")
	}
	if JudgeIPv6(nil, &ipinfo.Info{Country: "RU"}).Status != Unknown {
		t.Fatal("no ipv4 info is unknown")
	}
}

func TestJudgeTimezone(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	moscow, _ := time.LoadLocation("Europe/Moscow")
	berlin, _ := time.LoadLocation("Europe/Berlin")
	if v := JudgeTimezone("Europe/Amsterdam", berlin, now); v.Status != OK {
		t.Fatalf("same offset is ok: %+v", v)
	}
	if v := JudgeTimezone("Europe/Amsterdam", moscow, now); v.Status != Leak {
		t.Fatalf("2h diff is a mismatch: %+v", v)
	}
	if v := JudgeTimezone("Europe/Kaliningrad", berlin, now); v.Status != OK {
		t.Fatalf("1h diff is tolerated: %+v", v)
	}
	if v := JudgeTimezone("America/New_York", moscow, now); v.Status != Leak {
		t.Fatalf("8h diff is a mismatch: %+v", v)
	}
	if v := JudgeTimezone("", moscow, now); v.Status != Unknown {
		t.Fatalf("empty tz is unknown: %+v", v)
	}
}

func TestJudgeWebRTC(t *testing.T) {
	exit := []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	cands := func(s ...string) []netip.Addr {
		var out []netip.Addr
		for _, x := range s {
			out = append(out, netip.MustParseAddr(x))
		}
		return out
	}
	if JudgeWebRTC(exit, cands("192.168.1.5", "203.0.113.9")).Status != OK {
		t.Fatal("private host + exit srflx is ok")
	}
	if JudgeWebRTC(exit, cands("95.167.1.1")).Status != Leak {
		t.Fatal("foreign public candidate is a leak")
	}
	if JudgeWebRTC(exit, nil).Status != OK {
		t.Fatal("no candidates (webrtc disabled) is ok")
	}
}
