//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "ariguard-bench: eBPF and the agent require linux")
	os.Exit(1)
}
