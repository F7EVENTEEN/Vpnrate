package ui

import (
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// When a VPN switches, Explorer can stall long enough for Shell_NotifyIcon
// calls to time out, and the icon may be dropped without the TaskbarCreated
// broadcast that the systray library listens for. The process keeps running
// but the user sees it "vanish". The keeper checks every few seconds that
// our icon still exists and, if not, sends our own tray window the
// TaskbarCreated message, which makes the library add the icon again.

var (
	user32                 = windows.NewLazySystemDLL("user32.dll")
	shell32                = windows.NewLazySystemDLL("shell32.dll")
	pEnumWindows           = user32.NewProc("EnumWindows")
	pGetClassName          = user32.NewProc("GetClassNameW")
	pPostMessage           = user32.NewProc("PostMessageW")
	pRegisterWindowMessage = user32.NewProc("RegisterWindowMessageW")
	pNotifyIconGetRect     = shell32.NewProc("Shell_NotifyIconGetRect")
)

const (
	trayClass  = "SystrayClass" // class name used by fyne.io/systray
	trayIconID = 100            // icon ID used by fyne.io/systray
)

type notifyIconIdentifier struct {
	Size uint32
	Wnd  uintptr
	ID   uint32
	Guid windows.GUID
}

func keepTrayIcon(stop <-chan struct{}) {
	name, _ := windows.UTF16PtrFromString("TaskbarCreated")
	msg, _, _ := pRegisterWindowMessage.Call(uintptr(unsafe.Pointer(name)))
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	var wnd uintptr
	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}
		if wnd == 0 {
			if wnd = findTrayWindow(); wnd == 0 {
				continue
			}
		}
		if !iconPresent(wnd) {
			log.Printf("tray: icon missing from the notification area, restoring")
			pPostMessage.Call(wnd, msg, 0, 0)
		}
	}
}

func iconPresent(wnd uintptr) bool {
	id := notifyIconIdentifier{Wnd: wnd, ID: trayIconID}
	id.Size = uint32(unsafe.Sizeof(id))
	var rect [4]int32
	hr, _, _ := pNotifyIconGetRect.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&rect)))
	return hr == 0 // S_OK
}

// findTrayWindow finds the systray window that belongs to this process.
func findTrayWindow() uintptr {
	pid := uint32(os.Getpid())
	var found uintptr
	cb := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var wpid uint32
		windows.GetWindowThreadProcessId(windows.HWND(hwnd), &wpid)
		if wpid != pid {
			return 1
		}
		buf := make([]uint16, 64)
		n, _, _ := pGetClassName.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if windows.UTF16ToString(buf[:n]) == trayClass {
			found = hwnd
			return 0
		}
		return 1
	})
	pEnumWindows.Call(cb, 0)
	return found
}
