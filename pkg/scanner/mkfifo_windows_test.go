//go:build windows

package scanner

import "errors"

func mkfifoFile(string) error { return errors.New("no named pipes") }
