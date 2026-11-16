package leak

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

// Minimal STUN (RFC 5389) Binding client: enough to learn the public
// address our UDP traffic leaves from.

const (
	stunMagic            = 0x2112A442
	attrMappedAddress    = 0x0001
	attrXorMappedAddress = 0x0020
)

var DefaultSTUNServers = []string{"stun.l.google.com:19302", "stun.cloudflare.com:3478"}

func BuildBindingRequest(txid [12]byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint32(b[4:8], stunMagic)
	copy(b[8:20], txid[:])
	return b
}

func ParseBindingResponse(b []byte, txid [12]byte) (netip.AddrPort, error) {
	if len(b) < 20 {
		return netip.AddrPort{}, errors.New("stun: short packet")
	}
	if binary.BigEndian.Uint16(b[0:2]) != 0x0101 {
		return netip.AddrPort{}, errors.New("stun: not a binding success response")
	}
	if binary.BigEndian.Uint32(b[4:8]) != stunMagic || [12]byte(b[8:20]) != txid {
		return netip.AddrPort{}, errors.New("stun: transaction mismatch")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	body := b[20:]
	if n > len(body) {
		return netip.AddrPort{}, errors.New("stun: truncated")
	}
	body = body[:n]
	var fallback netip.AddrPort
	for len(body) >= 4 {
		typ := binary.BigEndian.Uint16(body[0:2])
		l := int(binary.BigEndian.Uint16(body[2:4]))
		if 4+l > len(body) {
			break
		}
		v := body[4 : 4+l]
		switch typ {
		case attrXorMappedAddress:
			if ap, ok := decodeAddr(v, true, txid); ok {
				return ap, nil
			}
		case attrMappedAddress:
			if ap, ok := decodeAddr(v, false, txid); ok {
				fallback = ap
			}
		}
		body = body[4+(l+3)&^3:]
	}
	if fallback.IsValid() {
		return fallback, nil
	}
	return netip.AddrPort{}, errors.New("stun: no mapped address")
}

func decodeAddr(v []byte, xor bool, txid [12]byte) (netip.AddrPort, bool) {
	if len(v) < 8 {
		return netip.AddrPort{}, false
	}
	port := binary.BigEndian.Uint16(v[2:4])
	var key [16]byte
	binary.BigEndian.PutUint32(key[0:4], stunMagic)
	copy(key[4:], txid[:])
	if xor {
		port ^= uint16(stunMagic >> 16)
	}
	switch v[1] {
	case 0x01:
		var a [4]byte
		copy(a[:], v[4:8])
		if xor {
			for i := range a {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a), port), true
	case 0x02:
		if len(v) < 20 {
			return netip.AddrPort{}, false
		}
		var a [16]byte
		copy(a[:], v[4:20])
		if xor {
			for i := range a {
				a[i] ^= key[i]
			}
		}
		return netip.AddrPortFrom(netip.AddrFrom16(a), port), true
	}
	return netip.AddrPort{}, false
}

// STUNQuery sends one Binding Request over UDPv4 and returns the mapped
// address. It retries once within the timeout, since UDP may drop packets.
func STUNQuery(ctx context.Context, server string, timeout time.Duration) (netip.AddrPort, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer c.Close()
	var txid [12]byte
	rand.Read(txid[:])
	req := BuildBindingRequest(txid)
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := c.Write(req); err != nil {
			return netip.AddrPort{}, err
		}
		step := time.Now().Add(time.Until(deadline) / time.Duration(2-attempt))
		c.SetReadDeadline(step)
		for {
			n, err := c.Read(buf)
			if err != nil {
				break
			}
			if ap, err := ParseBindingResponse(buf[:n], txid); err == nil {
				return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), nil
			}
		}
	}
	return netip.AddrPort{}, errors.New("stun: no response from " + server)
}

// UDPExitIP queries the given servers in order and returns the first answer.
func UDPExitIP(ctx context.Context, servers []string) (netip.Addr, error) {
	var errs []error
	for _, s := range servers {
		ap, err := STUNQuery(ctx, s, 3*time.Second)
		if err == nil {
			return ap.Addr(), nil
		}
		errs = append(errs, err)
	}
	return netip.Addr{}, errors.Join(errs...)
}
