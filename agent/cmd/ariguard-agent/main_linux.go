//go:build linux

// Command ariguard-agent loads the ariguard eBPF object, applies a policy
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
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
	"github.com/CosminMilica/ariguard/agent/internal/audit/ringbuf"
	"github.com/CosminMilica/ariguard/agent/internal/loader"
	"github.com/CosminMilica/ariguard/agent/internal/metrics"
	"github.com/CosminMilica/ariguard/agent/internal/metrics/metricmap"
	"github.com/CosminMilica/ariguard/agent/internal/podmeta"
	"github.com/CosminMilica/ariguard/agent/internal/podsync"
	"github.com/CosminMilica/ariguard/agent/internal/podsync/podmap"
	"github.com/CosminMilica/ariguard/agent/internal/policy"
	"github.com/CosminMilica/ariguard/agent/internal/policy/kmap"
	"github.com/CosminMilica/ariguard/agent/internal/sink"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

const podSyncInterval = 2 * time.Second

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("ariguard-agent failed", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	objectPath := flag.String("object", "", "path to the ariguard eBPF object (required)")
	bundlePath := flag.String("bundle", "", "path to the policy bundle v3 (required)")
	auditOut := flag.String("audit-out", "-", `audit JSON lines output file, "-" for stdout`)
	kubeconfig := flag.String("kubeconfig", "", "kubeconfig for pod names (empty: in-cluster config)")
	enforce := flag.Bool("enforce", false, "kill on matching kill actions in pod cgroups (default: detect only)")
	deny := flag.Bool("deny", false, "refuse deny-action syscalls with -EPERM via BPF LSM where a hook exists (needs --enforce and a kernel with BPF LSM; falls back to kill otherwise)")
	metricsAddr := flag.String("metrics-addr", "", `Prometheus listen address such as ":9102" (empty: disabled)`)
	sinkURL := flag.String("sink-url", "", `console base URL such as "http://console:8080" (empty: disabled)`)
	flag.Parse()
	if *objectPath == "" || *bundlePath == "" {
		flag.Usage()
		return errors.New("--object and --bundle are required")
	}
	if *deny && !*enforce {
		log.Warn("--deny has no effect without --enforce; deny tokens are only armed under enforcement")
	}

	out, closeOut, err := openOutput(*auditOut)
	if err != nil {
		return err
	}
	defer closeOut()

	obj, err := loader.Load(*objectPath, *deny, log)
	if err != nil {
		return err
	}
	defer func() {
		if err := obj.Close(); err != nil {
			log.Warn("detach", "err", err)
		}
	}()
	maps := kmap.KernelMaps{
		Policy:      obj.Maps.Policy,
		Rules:       obj.Maps.Rules,
		Transitions: obj.Maps.Transitions,
		Bindings:    obj.Maps.Bindings,
	}

	var names audit.Names
	bundle, err := applyBundle(maps, &names, *bundlePath, *enforce)
	if err != nil {
		return err
	}
	log.Info("policy applied", "bundle", *bundlePath, "enforce", *enforce)

	if err := obj.Attach(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var snk *sink.Sink
	if *sinkURL != "" {
		snk = sink.New(*sinkURL, sink.Registration{
			Node:           sink.NodeName(os.Getenv),
			Kernel:         kernelRelease(),
			Enforce:        *enforce,
			HooksAttached:  obj.HooksAttached(),
			HooksTotal:     int(fsm.NumHooks),
			AuditRingBytes: int(obj.Maps.Audit.MaxEntries()),
			MetricsAddr:    sink.AdvertiseAddr(*metricsAddr, os.Getenv),
		}, log)
		snk.SetBundle(sink.RulesFromBundle(bundle))
		snk.Register(ctx)
		out = io.MultiWriter(out, snk)
	}
	node := sink.NodeName(os.Getenv)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				b, err := applyBundle(maps, &names, *bundlePath, *enforce)
				if err != nil {
					log.Error("policy reload failed", "bundle", *bundlePath, "err", err)
					continue
				}
				snk.SetBundle(sink.RulesFromBundle(b))
				snk.Register(ctx)
				log.Info("policy reloaded", "bundle", *bundlePath)
			}
		}
	}()

	client, err := podmeta.NewClient(*kubeconfig)
	if err != nil {
		log.Warn("no Kubernetes API, audit lines carry no pod names", "err", err)
	}
	pods := podmeta.New(podmeta.DefaultCgroupRoot, client, log)

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		podsync.Run(ctx, podmap.Map{M: obj.Maps.Pods}, pods, podSyncInterval, log)
	}()
	if snk != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("pushing to console", "url", *sinkURL)
			snk.Run(ctx)
		}()
	}
	if *metricsAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log.Info("serving metrics", "addr", *metricsAddr)
			if err := metrics.Serve(ctx, *metricsAddr, metricmap.Reader{
				M: obj.Maps.Metrics, Pods: obj.Maps.Pods, State: obj.Maps.State,
				Names: &names, Resolver: pods, Node: node,
			}); err != nil {
				log.Error("metrics server", "err", err)
				stop()
			}
		}()
	}

	log.Info("streaming audit", "out", *auditOut)
	err = ringbuf.Stream(ctx, obj.Maps.Audit, out, &names, pods, log)
	stop()
	return err
}

func applyBundle(m policy.Maps, names *audit.Names, path string, enforce bool) (fsm.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return fsm.Bundle{}, fmt.Errorf("read bundle: %w", err)
	}
	b, err := fsm.UnmarshalBundle(data)
	if err != nil {
		return fsm.Bundle{}, fmt.Errorf("decode bundle %s: %w", path, err)
	}
	if err := policy.Apply(m, b, policy.WithEnforce(enforce)); err != nil {
		return fsm.Bundle{}, fmt.Errorf("apply bundle %s: %w", path, err)
	}
	names.Store(b.Meta)
	return *b, nil
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return unix.ByteSliceToString(u.Release[:])
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
