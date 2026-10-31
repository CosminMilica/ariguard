//go:build linux

// Command statewall-agent loads the statewall eBPF object, applies a policy
// bundle and streams audit events as JSON lines (dev mode, D7).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/CosminMilica/statewall/agent/internal/audit"
	"github.com/CosminMilica/statewall/agent/internal/loader"
	"github.com/CosminMilica/statewall/agent/internal/policy"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("statewall-agent failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	objectPath := flag.String("object", "", "path to the statewall eBPF object (required)")
	bundlePath := flag.String("bundle", "", "path to the policy bundle v2 (required)")
	auditOut := flag.String("audit-out", "-", `audit JSON lines output file, "-" for stdout`)
	flag.Parse()
	if *objectPath == "" || *bundlePath == "" {
		flag.Usage()
		return errors.New("--object and --bundle are required")
	}

	out, closeOut, err := openOutput(*auditOut)
	if err != nil {
		return err
	}
	defer closeOut()

	obj, err := loader.Load(*objectPath, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := obj.Close(); err != nil {
			log.Warn("detach", "err", err)
		}
	}()
	maps := policy.KernelMaps{
		Transitions: obj.Maps.Transitions,
		Bindings:    obj.Maps.Bindings,
		Dims:        obj.Maps.Dims,
	}

	if err := applyBundle(maps, *bundlePath); err != nil {
		return err
	}
	log.Info("policy applied", "bundle", *bundlePath)

	if err := obj.Attach(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := applyBundle(maps, *bundlePath); err != nil {
					log.Error("policy reload failed", "bundle", *bundlePath, "err", err)
					continue
				}
				log.Info("policy reloaded", "bundle", *bundlePath)
			}
		}
	}()

	log.Info("streaming audit", "out", *auditOut)
	return audit.Stream(ctx, obj.Maps.Audit, out, log)
}

func applyBundle(m policy.Maps, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	b, err := fsm.UnmarshalBundle(data)
	if err != nil {
		return fmt.Errorf("decode bundle %s: %w", path, err)
	}
	if err := policy.Apply(m, b); err != nil {
		return fmt.Errorf("apply bundle %s: %w", path, err)
	}
	return nil
}

func openOutput(path string) (io.Writer, func(), error) {
	if path == "-" {
		return os.Stdout, func() {}, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit output: %w", err)
	}
	return f, func() { _ = f.Close() }, nil
}
