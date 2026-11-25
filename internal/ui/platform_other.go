//go:build !windows

package ui

import (
	"errors"
	"os/exec"
	"runtime"
)

var errUnsupported = errors.New("not supported on this platform yet")

func AutostartRegistered() bool                  { return false }
func AutostartStatus() (task, run bool)          { return false, false }
func EnableAutostart(exe string) (string, error) { return "", errUnsupported }
func DisableAutostart() error                    { return errUnsupported }
func Notify(title, msg string) error             { return errUnsupported }

func OpenURL(u string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}

func keepTrayIcon(stop <-chan struct{}) {}
