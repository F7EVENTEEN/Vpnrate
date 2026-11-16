// Package ui is the desktop shell: tray icon, notifications and autostart.
package ui

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/png"
	"math"
)

var (
	Green  = color.RGBA{0x22, 0xc5, 0x5e, 0xff}
	Yellow = color.RGBA{0xf5, 0x9e, 0x0b, 0xff}
	Red    = color.RGBA{0xef, 0x44, 0x44, 0xff}
	Gray   = color.RGBA{0x9c, 0xa3, 0xaf, 0xff}
)

// CircleICO draws an anti-aliased filled circle and wraps the PNG in an
// ICO container (Windows tray icons must be ICO; PNG payloads are fine).
func CircleICO(c color.RGBA) []byte {
	const n = 32
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	r := float64(n)/2 - 2
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			d := math.Hypot(float64(x)+.5-n/2, float64(y)+.5-n/2)
			a := math.Max(0, math.Min(1, r-d+.5))
			if a > 0 {
				img.SetRGBA(x, y, color.RGBA{uint8(float64(c.R) * a), uint8(float64(c.G) * a), uint8(float64(c.B) * a), uint8(255 * a)})
			}
		}
	}
	var p bytes.Buffer
	png.Encode(&p, img)

	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, []uint16{0, 1, 1}) // reserved, type=icon, count
	b.Write([]byte{n, n, 0, 0})                              // w, h, colors, reserved
	binary.Write(&b, binary.LittleEndian, []uint16{1, 32})   // planes, bpp
	binary.Write(&b, binary.LittleEndian, []uint32{uint32(p.Len()), 22})
	b.Write(p.Bytes())
	return b.Bytes()
}
