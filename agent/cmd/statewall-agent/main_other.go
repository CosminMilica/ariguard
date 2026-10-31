//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "statewall-agent: eBPF requires linux")
	os.Exit(1)
}
