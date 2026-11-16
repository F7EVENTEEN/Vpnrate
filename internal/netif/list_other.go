//go:build !windows

package netif

import "net"

func List() ([]Iface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if addrs, _ := i.Addrs(); len(addrs) == 0 {
			continue
		}
		out = append(out, Iface{Name: i.Name})
	}
	return out, nil
}
