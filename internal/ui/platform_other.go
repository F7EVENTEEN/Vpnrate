//go:build !windows

package ui

import (
	"errors"
	"os/exec"
	"runtime"
)

var errUnsupported = errors.New("not supported on this platform yet")

func AutostartEnabled() bool         { return false }
func SetAutostart(on bool) error     { return errUnsupported }
func Notify(title, msg string) error { return errUnsupported }

func OpenURL(u string) error {
	if runtime.GOOS == "darwin" {
		return exec.Command("open", u).Start()
	}
	return exec.Command("xdg-open", u).Start()
}
