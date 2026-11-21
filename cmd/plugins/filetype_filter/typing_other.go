//go:build !linux

package main

import (
	"os"

	"github.com/vimeo/go-magic/magic"
)

func closeCookies() {}

// typeOf types the file at location by its name: without /proc there is no
// descriptor to hand to libmagic.
func typeOf(location string) (t typed, err error) {
	info, err := os.Stat(location)
	if err != nil {
		return typed{}, err
	}
	t.size = info.Size()
	return withType(t, magic.MimeFromFile(location))
}
