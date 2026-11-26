package quarantine

// syncDir does nothing: Windows has no way to flush a directory. Replaced in
// tests.
var syncDir = func(string) error { return nil }
