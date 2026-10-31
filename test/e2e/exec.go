//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Default per-command timeouts. Build and image load are slow; everything else
// is a quick control-plane or kernel call.
const (
	buildTimeout   = 25 * time.Minute
	kubectlTimeout = 3 * time.Minute
	shortTimeout   = 30 * time.Second
)

// run executes name with args and returns its captured stdout and stderr. The
// caller owns the context (and therefore the timeout).
func run(ctx context.Context, name string, args ...string) (stdout, stderr string, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err = cmd.Run()
	return out.String(), errb.String(), err
}

// runFatal runs name and fails the test on a non-zero exit, dumping both streams.
func runFatal(t *testing.T, timeout time.Duration, name string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, errOut, err := run(ctx, name, args...)
	if err != nil {
		t.Fatalf("%s %s: %v\n--- stdout ---\n%s\n--- stderr ---\n%s",
			name, strings.Join(args, " "), err, out, errOut)
	}
	return out
}

// runTry runs name without failing the test; used inside polling loops.
func runTry(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, errOut, err := run(ctx, name, args...)
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (stderr: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(errOut))
	}
	return out, nil
}

// kubeconfigArgs prepends --kubeconfig/--context from the environment so the
// harness talks to the kind cluster the same way an operator would.
func kubeconfigArgs(args ...string) []string {
	var base []string
	if kc := os.Getenv("ARIGUARD_KUBECONFIG"); kc != "" {
		base = append(base, "--kubeconfig", kc)
	}
	if ctxName := kubeContext(); ctxName != "" {
		base = append(base, "--context", ctxName)
	}
	return append(base, args...)
}

func kubeContext() string {
	if v, ok := os.LookupEnv("ARIGUARD_KUBE_CONTEXT"); ok {
		return v
	}
	return "kind-ariguard-dev"
}

// kubectl runs kubectl and fails the test on error.
func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	return runFatal(t, kubectlTimeout, "kubectl", kubeconfigArgs(args...)...)
}

// kubectlTry runs kubectl inside a polling loop without failing the test.
func kubectlTry(timeout time.Duration, args ...string) (string, error) {
	return runTry(timeout, "kubectl", kubeconfigArgs(args...)...)
}

// bpftoolMapDump dumps a map by name as JSON from the VM host kernel. The maps
// live in the host kernel (the DaemonSet shares it), so this runs on the node
// via sudo, not inside the pod image.
func bpftoolMapDump(t *testing.T, mapName string) []bpfEntry {
	t.Helper()
	out := runFatal(t, shortTimeout, "sudo", "-n", "bpftool", "map", "dump", "name", mapName, "-j")
	entries, err := parseMapDump([]byte(out))
	if err != nil {
		t.Fatalf("parse bpftool dump of %s: %v\noutput:\n%s", mapName, err, out)
	}
	return entries
}

// makeTarget runs one or more Makefile targets from the repository root.
func makeTarget(timeout time.Duration, targets ...string) error {
	_, err := runTry(timeout, "make", append([]string{"-C", repoRoot()}, targets...)...)
	return err
}

// repoRoot resolves the repository root from this source file's location, which
// matches the checkout path inside the VM (the repo is mounted at the same path).
func repoRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
