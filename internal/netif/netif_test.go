package netif

import "testing"

func TestIsTunnel(t *testing.T) {
	tunnels := []Iface{
		{Name: "wg0", Description: "WireGuard Tunnel"},
		{Name: "MyVPN", Description: "Wintun Userspace Tunnel"},
		{Name: "Ethernet 3", Description: "TAP-Windows Adapter V9"},
		{Name: "OpenVPN Data Channel Offload", Description: "OpenVPN Data Channel Offload"},
		{Name: "AmneziaVPN", Description: "AmneziaWG Tunnel"},
		{Name: "utun3"},
		{Name: "tun0"},
		{Name: "outline-tap0", Description: "TAP-Windows Adapter V9 for Outline"},
		{Name: "sing-tun", Description: "sing-box TUN"},
		{Name: "Hiddify", Description: "Hiddify Tunnel"},
		{Name: "Local Area Connection", Description: "Some adapter", Type: ifTypeTunnel},
		{Name: "ppp0", Type: ifTypePPP},
	}
	for _, i := range tunnels {
		if !IsTunnel(i) {
			t.Errorf("expected tunnel: %+v", i)
		}
	}
	normal := []Iface{
		{Name: "Wi-Fi", Description: "Intel(R) Wi-Fi 6 AX201 160MHz"},
		{Name: "Ethernet", Description: "Realtek PCIe GbE Family Controller"},
		{Name: "vEthernet (WSL)", Description: "Hyper-V Virtual Ethernet Adapter"},
		{Name: "Loopback Pseudo-Interface 1"},
		{Name: "Bluetooth Network Connection", Description: "Bluetooth Device (Personal Area Network)"},
		{Name: "eth0"},
		{Name: "en0"},
	}
	for _, i := range normal {
		if IsTunnel(i) {
			t.Errorf("not a tunnel: %+v", i)
		}
	}
}

func TestKeyStable(t *testing.T) {
	a := Iface{Name: "wg0", Description: "WireGuard Tunnel"}
	if a.Key() != "wg0" {
		t.Fatalf("key = %q", a.Key())
	}
}
