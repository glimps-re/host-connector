package plugins

import "errors"

// ErrUnsafeExecutable is wrapped by every error CheckExecutable returns.
var ErrUnsafeExecutable = errors.New("unsafe executable")
