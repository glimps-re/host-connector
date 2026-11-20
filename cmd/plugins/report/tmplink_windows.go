package main

// linkTemp does nothing on Windows: the browser uses the folder of its rendering
// as it is, and there is no Unix socket.
func linkTemp(string) (string, error) { return "", nil }

// removeTempLink does nothing on Windows: linkTemp makes no link.
func removeTempLink(string) error { return nil }

// purgeTempLinks does nothing on Windows: linkTemp makes no link.
func purgeTempLinks() (int, error) { return 0, nil }
