package main

// pinLinkBase does nothing on Windows: there is no link.
func pinLinkBase() (unpin func()) { return func() {} }
