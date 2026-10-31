//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ariguard-agent: eBPF requires linux")
	os.Exit(1)
}
