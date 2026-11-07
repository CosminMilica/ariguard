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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
	"github.com/CosminMilica/ariguard/agent/internal/audit/ringbuf"
	"github.com/CosminMilica/ariguard/agent/internal/hooks"
	"github.com/CosminMilica/ariguard/agent/internal/learn"
	"github.com/CosminMilica/ariguard/agent/internal/learn/learnring"
	"github.com/CosminMilica/ariguard/agent/internal/loader"
	"github.com/CosminMilica/ariguard/agent/internal/metrics"
	"github.com/CosminMilica/ariguard/agent/internal/metrics/metricmap"
	"github.com/CosminMilica/ariguard/agent/internal/mutes"
	"github.com/CosminMilica/ariguard/agent/internal/podmeta"
	"github.com/CosminMilica/ariguard/agent/internal/podsync"
	"github.com/CosminMilica/ariguard/agent/internal/podsync/podmap"
	"github.com/CosminMilica/ariguard/agent/internal/policy"
	"github.com/CosminMilica/ariguard/agent/internal/policy/kmap"
	"github.com/CosminMilica/ariguard/agent/internal/policysync"
	"github.com/CosminMilica/ariguard/agent/internal/responder"
	"github.com/CosminMilica/ariguard/agent/internal/sink"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

const podSyncInterval = 2 * time.Second

// muteInterval is how often the agent refreshes the operator allowlist from the console (F5).
const muteInterval = 10 * time.Second

// policyInterval is how often the agent polls the control plane for a newer policy bundle (F7).
const policyInterval = 15 * time.Second

// mutedCgroups is a podsync.Source that drops muted pods' cgroups so AG_PODS (the kill-gate) never
// contains them. src lists the node's pod cgroups; pods resolves cgroup id -> pod metadata. It also
// drops pods in observe-only namespaces: those are detected but never killed (yet, unlike mutes,
// their events still count as attack, because they are not on the mute list the console reads).
type mutedCgroups struct {
	src     podsync.Source
	pods    *podmeta.Resolver
	muted   *mutes.Set
	observe *mutes.Set // observe-only namespaces
}

func (m mutedCgroups) PodCgroups() []uint64 {
	all := m.src.PodCgroups()
	out := make([]uint64, 0, len(all))
	for _, c := range all {
		info := m.pods.Lookup(context.Background(), c)
		if m.muted.Has(info.Pod) || m.observe.Has(info.Namespace) {
			continue
		}
		out = append(out, c)
	}
	return out
}

// learnCgroups is a podsync.Source that keeps only the cgroups of pods in an opt-in namespace set,
// so AG_LEARN_PODS (the learn-mode emit gate) holds just those (F11). src lists the node's pod
// cgroups; pods resolves cgroup id -> pod metadata. An empty set yields no cgroups (no emit).
type learnCgroups struct {
	src   podsync.Source
	pods  *podmeta.Resolver
	learn *mutes.Set
}

func (l learnCgroups) PodCgroups() []uint64 {
	all := l.src.PodCgroups()
	out := make([]uint64, 0, len(all))
	for _, c := range all {
		if l.learn.Has(l.pods.Lookup(context.Background(), c).Namespace) {
			out = append(out, c)
		}
	}
	return out
}

// podMeta adapts the pod resolver to learn.Meta: a cgroup -> (namespace, pod) lookup for the source
// field of a learn-mode trace.
type podMeta struct{ pods *podmeta.Resolver }

func (m podMeta) Pod(cgroup uint64) (string, string) {
	info := m.pods.Lookup(context.Background(), cgroup)
	return info.Namespace, info.Pod
}

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
	bpfStats := flag.Bool("bpf-stats", false, "enable BPF_STATS_RUN_TIME and expose per-program run-time metrics (small per-event overhead)")
	sinkURL := flag.String("sink-url", "", `console base URL such as "http://console:8080" (empty: disabled)`)
	authToken := flag.String("auth-token", os.Getenv("ARIGUARD_TOKEN"), "shared bearer token for the console control plane (empty: none)")
	isolate := flag.String("isolate", "off", "autonomous workload isolation on a confirmed terminal mitigation: off|dryrun|on (on applies a deny-all NetworkPolicy; dryrun only labels the pod; needs Kubernetes API access)")
	isolateFallback := flag.String("isolate-fallback", "off", "extra isolation for CNIs that ignore NetworkPolicy (e.g. kindnet): off|evict (evict deletes the quarantined pod to cut its network now; destructive)")
	policySync := flag.Bool("policy-sync", true, "poll the console for a newer policy bundle and hot-swap it (control plane, F7; needs --sink-url)")
	learnMode := flag.Bool("learn", false, "learn-mode: emit full-syscall traces from this node's pods to the console for novel-chain mining (F11; needs --sink-url). Adds a second program per hook and extra load; off by default")
	learnWindow := flag.Duration("learn-window", 10*time.Second, "learn-mode: idle gap after which a per-process syscall trace is closed and posted")
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

	// enforceMode is the live fleet mode: the launch flag initially, then whatever the console's
	// global toggle sets (hot-swapped below). lastBundle holds the bytes last written to the kernel
	// so a mode switch can re-apply them under the new mode. Both are guarded by policyMu once the
	// goroutines below start; here, before any goroutine, no lock is needed.
	enforceMode := &atomic.Bool{}
	enforceMode.Store(*enforce)

	var names audit.Names
	lastBundle, err := os.ReadFile(*bundlePath)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	bundle, err := applyBundleData(maps, &names, lastBundle, enforceMode.Load())
	if err != nil {
		return err
	}
	log.Info("policy applied", "bundle", *bundlePath, "enforce", enforceMode.Load())

	if err := obj.Attach(); err != nil {
		return err
	}

	var progs map[string]*ebpf.Program
	if *bpfStats {
		closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
		if err != nil {
			return fmt.Errorf("enable BPF run-time stats: %w", err)
		}
		defer func() { _ = closer.Close() }()
		progs = obj.Programs()
		log.Info("BPF run-time stats enabled", "programs", len(progs))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var snk *sink.Sink
	if *sinkURL != "" {
		snk = sink.New(*sinkURL, sink.Registration{
			Node:           sink.NodeName(os.Getenv),
			Kernel:         kernelRelease(),
			Enforce:        enforceMode.Load(),
			HooksAttached:  obj.HooksAttached(),
			HooksTotal:     int(fsm.NumHooks),
			AuditRingBytes: int(obj.Maps.Audit.MaxEntries()),
			MetricsAddr:    sink.AdvertiseAddr(*metricsAddr, os.Getenv),
		}, log)
		snk.SetToken(*authToken)
		snk.SetBundle(sink.RulesFromBundle(bundle))
		snk.Register(ctx)
		out = io.MultiWriter(out, snk)
	}
	node := sink.NodeName(os.Getenv)

	// policyMu serialises every policy hot-swap: the SIGHUP file reload and the control-plane
	// poller must not write the kernel maps at the same time.
	var policyMu sync.Mutex

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				data, rerr := os.ReadFile(*bundlePath)
				if rerr != nil {
					log.Error("policy reload failed", "bundle", *bundlePath, "err", rerr)
					continue
				}
				policyMu.Lock()
				enf := enforceMode.Load()
				b, applied, err := applySwap(maps, &names, data, enf, lastBundle, enf, log)
				if applied {
					lastBundle = data
				}
				policyMu.Unlock()
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

	// Control plane (F7): poll the console for a newer bundle and hot-swap it, no image rebuild.
	if snk != nil && *policySync {
		go policysync.Poll(ctx, policyInterval,
			snk.Policy,
			func(data []byte) error {
				policyMu.Lock()
				enf := enforceMode.Load()
				b, applied, err := applySwap(maps, &names, data, enf, lastBundle, enf, log)
				if applied {
					lastBundle = data
				}
				policyMu.Unlock()
				if err != nil {
					return err
				}
				snk.SetBundle(sink.RulesFromBundle(b))
				snk.Register(ctx)
				return nil
			}, log)
		log.Info("control-plane policy sync enabled", "interval", policyInterval)
	}

	// Global enforcement mode (F10 UI): poll the console's desired detect/enforce mode and hot-swap
	// the current bundle under it, no restart. Unset on the console = keep the launch-flag mode.
	if snk != nil {
		go func() {
			tick := time.NewTicker(muteInterval)
			defer tick.Stop()
			switchMode := func() {
				enf, set, err := snk.Mode(ctx)
				if err != nil || !set || enf == enforceMode.Load() {
					return
				}
				policyMu.Lock()
				old := enforceMode.Load()
				b, applied, aerr := applySwap(maps, &names, lastBundle, enf, lastBundle, old, log)
				if applied {
					enforceMode.Store(enf)
				}
				policyMu.Unlock()
				if aerr != nil {
					log.Error("enforcement mode switch failed", "enforce", enf, "err", aerr)
					return
				}
				snk.SetEnforce(enf)
				snk.SetBundle(sink.RulesFromBundle(b))
				snk.Register(ctx)
				log.Info("enforcement mode switched", "enforce", enf)
			}
			switchMode()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
					switchMode()
				}
			}
		}()
	}

	client, err := podmeta.NewClient(*kubeconfig)
	if err != nil {
		log.Warn("no Kubernetes API, audit lines carry no pod names", "err", err)
	}
	pods := podmeta.New(podmeta.DefaultCgroupRoot, client, log)

	isolateMode, err := responder.ParseMode(*isolate)
	if err != nil {
		log.Error("invalid --isolate", "err", err)
		os.Exit(2)
	}
	isolateFb, err := responder.ParseFallback(*isolateFallback)
	if err != nil {
		log.Error("invalid --isolate-fallback", "err", err)
		os.Exit(2)
	}

	// Operator allowlist (F5): polled from the console; muted pods are neither killed (excluded
	// from AG_PODS below) nor quarantined (responder consults muteSet.Has). Muting an already
	// quarantined pod also releases it (F6), via the responder's ReleaseLoop.
	muteSet := mutes.New()
	// Observe-only namespaces: like mutes (no kill, no quarantine, release of an already-isolated
	// pod), but keyed by namespace and NOT reported as muted, so the console still counts the traffic
	// as attack. Lets a discovery honeypot run next to an enforcing fleet and still promote its rules.
	observeSet := mutes.New()
	if snk != nil {
		go mutes.Poll(ctx, muteSet, muteInterval, snk.Mutes, log)
		go mutes.Poll(ctx, observeSet, muteInterval, snk.ObserveNamespaces, log)
	}

	rsp := responder.New(client, isolateMode, isolateFb, muteSet.Has, observeSet.Has, func(ns, pod, rule, mode string) {
		snk.Quarantine(context.Background(), ns, pod, rule, mode)
	}, func(ns, pod string) {
		snk.Release(context.Background(), ns, pod)
	}, log)
	if rsp != nil {
		log.Info("autonomous workload isolation enabled", "mode", isolateMode.String(), "fallback", isolateFb.String())
		go rsp.ReleaseLoop(ctx, muteInterval)
	}

	var wg sync.WaitGroup
	defer wg.Wait()
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Kill-gating honors mutes and observe-only namespaces: drop their cgroups from AG_PODS so no
		// SIGKILL fires.
		src := podsync.Source(pods)
		if snk != nil {
			src = mutedCgroups{src: pods, pods: pods, muted: muteSet, observe: observeSet}
		}
		podsync.Run(ctx, podmap.Map{M: obj.Maps.Pods}, src, podSyncInterval, log)
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
				Names: &names, Resolver: pods, Node: node, Progs: progs,
			}); err != nil {
				log.Error("metrics server", "err", err)
				stop()
			}
		}()
	}

	// Learn-mode (F11): emit full-syscall traces from this node's pods for novel-chain mining. Attach
	// the dedicated learn programs, mirror pod cgroups into the opt-in gate (AG_LEARN_PODS), drain the
	// ring into per-process traces and post them. Needs a sink (the console mines the traces).
	var threat *learn.ThreatSet
	if *learnMode {
		if snk == nil {
			log.Warn("--learn ignored: needs --sink-url to post traces")
		} else {
			if err := obj.AttachLearn(); err != nil {
				return fmt.Errorf("attach learn programs: %w", err)
			}
			threat = learn.NewThreatSet(0)
			asm := learn.NewAssembler(
				learn.Config{Window: *learnWindow},
				podMeta{pods: pods}, threat, node, hooks.Name, snk.Traces, log,
			)
			// Gate: mirror only pods in the opt-in learn namespaces (polled from the console) into
			// AG_LEARN_PODS, so emit is scoped and off by default (empty set = no emit).
			learnSet := mutes.New()
			go mutes.Poll(ctx, learnSet, muteInterval, snk.LearnNamespaces, log)
			wg.Add(1)
			go func() {
				defer wg.Done()
				src := learnCgroups{src: pods, pods: pods, learn: learnSet}
				podsync.Run(ctx, podmap.Map{M: obj.Maps.LearnPods}, src, podSyncInterval, log)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				asm.Run(ctx)
			}()
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := learnring.Drain(ctx, obj.Maps.Learn, asm, log); err != nil {
					log.Error("learn drain", "err", err)
				}
			}()
			log.Info("learn-mode enabled", "window", *learnWindow)
		}
	}
	var markThreat func(uint64)
	if threat != nil {
		markThreat = threat.Mark
	}

	log.Info("streaming audit", "out", *auditOut)
	err = ringbuf.Stream(ctx, obj.Maps.Audit, obj.Maps.Ppid, obj.Maps.ConnDst, obj.Maps.Path, obj.Maps.Argv, out, &names, pods, rsp, markThreat, log)
	stop()
	return err
}

// applyBundleData hot-swaps a bundle given as bytes (from a file or the control plane) into the
// kernel maps without reloading programs.
func applyBundleData(m policy.Maps, names *audit.Names, data []byte, enforce bool) (fsm.Bundle, error) {
	b, err := fsm.UnmarshalBundle(data)
	if err != nil {
		return fsm.Bundle{}, fmt.Errorf("decode bundle: %w", err)
	}
	if err := policy.Apply(m, b, policy.WithEnforce(enforce)); err != nil {
		return fsm.Bundle{}, fmt.Errorf("apply bundle: %w", err)
	}
	names.Store(b.Meta)
	return *b, nil
}

// applySwap applies data under enforce and, on failure, rolls the kernel back to lastGood under
// rollbackEnforce — so a failed hot-swap never leaves AG_POLICY zeroed and detection/enforcement
// disabled (fail-open). It returns the applied bundle, whether the new data took effect, and the
// apply error. If the rollback itself fails the policy may be degraded, which is logged loudly.
func applySwap(m policy.Maps, names *audit.Names, data []byte, enforce bool, lastGood []byte, rollbackEnforce bool, log *slog.Logger) (fsm.Bundle, bool, error) {
	b, err := applyBundleData(m, names, data, enforce)
	if err == nil {
		return b, true, nil
	}
	if lastGood != nil {
		if rb, rerr := applyBundleData(m, names, lastGood, rollbackEnforce); rerr != nil {
			log.Error("policy swap failed AND rollback failed; policy may be degraded", "err", err, "rollback_err", rerr)
		} else {
			log.Error("policy swap failed; rolled back to last-good policy", "err", err)
			return rb, false, err
		}
	}
	return fsm.Bundle{}, false, err
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
