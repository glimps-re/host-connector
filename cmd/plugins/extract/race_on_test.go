//go:build race

package main

// slowdown is how much slower the race detector makes the code: the time bounds
// of the tests are multiplied by it.
const slowdown = 60
