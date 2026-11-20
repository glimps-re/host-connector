//go:build windows

package safepath

import "errors"

func mkfifo(string) error { return errors.New("no named pipes") }
