package netif

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// List returns up interfaces with an address, including the adapter
// description (e.g. "WireGuard Tunnel"), which net.Interfaces does not expose.
func List() ([]Iface, error) {
	size := uint32(16 * 1024)
	for range 3 {
		buf := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_DNS_SERVER, 0, first, &size)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue
		}
		if err != nil {
			return nil, err
		}
		var out []Iface
		for a := first; a != nil; a = a.Next {
			if a.OperStatus != windows.IfOperStatusUp || a.FirstUnicastAddress == nil {
				continue
			}
			out = append(out, Iface{
				Name:        windows.UTF16PtrToString(a.FriendlyName),
				Description: windows.UTF16PtrToString(a.Description),
				Type:        a.IfType,
			})
		}
		return out, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}
