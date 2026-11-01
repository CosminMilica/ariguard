// Package sink pushes node registration and audit events to the console backend over HTTP.
package sink

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/CosminMilica/ariguard/agent/internal/audit"
	"github.com/CosminMilica/ariguard/agent/internal/hooks"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

const (
	// BatchSize is the number of buffered events that triggers an immediate flush.
	BatchSize = 64
	// FlushInterval bounds how long an event waits in the buffer.
	FlushInterval = time.Second
	// HeartbeatInterval is the period of the register heartbeat.
	HeartbeatInterval = 10 * time.Second

	// ObserveInterval is the minimum spacing between forwarded repeats of an observe event.
	ObserveInterval = 10 * time.Second

	maxBuffered = 4096
	maxThrottle = 4096
	postTimeout = 5 * time.Second
)

// Rule is the per-rule metadata of the active bundle.
type Rule struct {
	Name           string           `json:"name"`
	Scope          string           `json:"scope"`
	NumStates      uint32           `json:"num_states"`
	WindowNs       uint64           `json:"window_ns"`
	TerminalAction string           `json:"terminal_action"`
	States         []string         `json:"states"`
	Events         []string         `json:"events"`
	TerminalFrom   uint32           `json:"terminal_from"`
	Transitions    []RuleTransition `json:"transitions"`
}

// RuleTransition is one meaningful cell of a rule's state machine.
type RuleTransition struct {
	From     string   `json:"from"`
	Event    string   `json:"event"`
	To       string   `json:"to"`
	Action   string   `json:"action"`
	Syscalls []string `json:"syscalls"`
}

// Bundle is the policy summary carried by a registration.
type Bundle struct {
	Rules []Rule `json:"rules"`
}

// Registration is the body of POST /api/v1/register.
type Registration struct {
	Node           string `json:"node"`
	Kernel         string `json:"kernel"`
	Enforce        bool   `json:"enforce"`
	HooksAttached  int    `json:"hooks_attached"`
	HooksTotal     int    `json:"hooks_total"`
	AuditRingBytes int    `json:"audit_ring_bytes"`
	MetricsAddr    string `json:"metrics_addr"`
	Bundle         Bundle `json:"bundle"`
	TsNs           uint64 `json:"ts_ns"`
}

// Event is an audit event tagged with the node that produced it.
type Event struct {
	audit.Event
	Node string `json:"node"`
}

// Sink buffers audit events and posts them, with registrations, to a base URL.
// A nil *Sink is a no-op.
type Sink struct {
	base   string
	info   Registration
	client *http.Client
	log    *slog.Logger
	now    func() time.Time

	mu     sync.Mutex
	buf    []Event
	rules  []Rule
	kick   chan struct{}
	posted sync.Mutex

	seen map[throttleKey]time.Time
}

type throttleKey struct {
	cgroup uint64
	rule   string
	to     string
}

// New returns a sink posting to baseURL; info carries the static registration fields.
func New(baseURL string, info Registration, log *slog.Logger) *Sink {
	return &Sink{
		base:   strings.TrimRight(baseURL, "/"),
		info:   info,
		client: &http.Client{Timeout: postTimeout},
		log:    log,
		now:    time.Now,
		kick:   make(chan struct{}, 1),
		seen:   map[throttleKey]time.Time{},
	}
}

// SetBundle records the rules reported by subsequent registrations.
func (s *Sink) SetBundle(rules []Rule) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()
}

// Registration returns the current registration body.
func (s *Sink) Registration() Registration {
	s.mu.Lock()
	r := s.info
	r.Bundle = Bundle{Rules: append([]Rule{}, s.rules...)}
	s.mu.Unlock()
	r.TsNs = uint64(s.now().UnixNano())
	return r
}

// Register posts the current registration; failures are logged.
func (s *Sink) Register(ctx context.Context) {
	if s == nil {
		return
	}
	if err := s.post(ctx, "/api/v1/register", s.Registration()); err != nil {
		s.log.Warn("sink register", "err", err)
	}
}

// allowLocked reports whether e should be forwarded: non-observe events and new
// (cgroup, rule, to) combinations always pass; repeated observe events pass at most
// once per ObserveInterval. Callers hold s.mu.
func (s *Sink) allowLocked(e audit.Event) bool {
	if e.Action != "observe" {
		return true
	}
	now := s.now()
	k := throttleKey{e.CgroupID, e.Rule, e.To}
	if last, ok := s.seen[k]; ok && now.Sub(last) < ObserveInterval {
		return false
	}
	if _, ok := s.seen[k]; !ok && len(s.seen) >= maxThrottle {
		s.pruneLocked(now)
	}
	s.seen[k] = now
	return true
}

func (s *Sink) pruneLocked(now time.Time) {
	var oldest throttleKey
	var oldestAt time.Time
	first := true
	for k, t := range s.seen {
		if now.Sub(t) >= ObserveInterval {
			delete(s.seen, k)
			continue
		}
		if first || t.Before(oldestAt) {
			oldest, oldestAt, first = k, t, false
		}
	}
	if len(s.seen) >= maxThrottle && !first {
		delete(s.seen, oldest)
	}
}

// Emit queues an event; it never blocks and drops the oldest event when the buffer is full.
// Repeated observe events are throttled, see allowLocked.
func (s *Sink) Emit(e audit.Event) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if !s.allowLocked(e) {
		s.mu.Unlock()
		return
	}
	if len(s.buf) >= maxBuffered {
		s.buf = s.buf[1:]
	}
	s.buf = append(s.buf, Event{Event: e, Node: s.info.Node})
	full := len(s.buf) >= BatchSize
	s.mu.Unlock()
	if full {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
}

// Write implements io.Writer for the audit JSON lines stream; it never fails.
func (s *Sink) Write(p []byte) (int, error) {
	if s == nil {
		return len(p), nil
	}
	for _, line := range bytes.Split(p, []byte{'\n'}) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(line, &e); err != nil {
			s.log.Warn("sink: skip malformed audit line", "err", err)
			continue
		}
		s.Emit(e)
	}
	return len(p), nil
}

var _ io.Writer = (*Sink)(nil)

// Run flushes buffered events every FlushInterval or when a batch fills, and
// sends the heartbeat registration, until ctx is done; it then flushes once more.
func (s *Sink) Run(ctx context.Context) {
	if s == nil {
		return
	}
	flush := time.NewTicker(FlushInterval)
	defer flush.Stop()
	beat := time.NewTicker(HeartbeatInterval)
	defer beat.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), postTimeout)
			s.Flush(fctx)
			cancel()
			return
		case <-flush.C:
			s.Flush(ctx)
		case <-s.kick:
			s.Flush(ctx)
		case <-beat.C:
			s.Register(ctx)
		}
	}
}

// Flush posts up to a batch of events at a time until the buffer is empty or a post fails.
// Events of a failed post are put back (bounded by the buffer cap).
func (s *Sink) Flush(ctx context.Context) {
	if s == nil {
		return
	}
	s.posted.Lock()
	defer s.posted.Unlock()
	for {
		s.mu.Lock()
		n := min(len(s.buf), BatchSize)
		if n == 0 {
			s.mu.Unlock()
			return
		}
		batch := append([]Event(nil), s.buf[:n]...)
		s.buf = s.buf[n:]
		s.mu.Unlock()
		if err := s.post(ctx, "/api/v1/audit", batch); err != nil {
			s.log.Warn("sink audit", "events", len(batch), "err", err)
			s.requeue(batch)
			return
		}
	}
}

func (s *Sink) requeue(batch []Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := append(batch, s.buf...)
	if len(all) > maxBuffered {
		all = all[len(all)-maxBuffered:]
	}
	s.buf = all
}

func (s *Sink) post(ctx context.Context, path string, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+path, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: status %d", path, resp.StatusCode)
	}
	return nil
}

// RulesFromBundle summarises the rules of b.
func RulesFromBundle(b fsm.Bundle) []Rule {
	rules := make([]Rule, len(b.Rules))
	for i, r := range b.Rules {
		out := Rule{
			Name:         fmt.Sprintf("%d", i),
			Scope:        map[uint32]string{fsm.ScopeCgroup: "cgroup", fsm.ScopeProcess: "process"}[r.Scope],
			NumStates:    r.NumStates,
			WindowNs:     r.WindowNs,
			TerminalFrom: r.TerminalFrom,
		}
		if i < len(b.Meta.Rules) {
			if m := b.Meta.Rules[i]; m.Name != "" {
				out.Name = m.Name
			}
			if m := b.Meta.Rules[i]; m.Scope != "" {
				out.Scope = m.Scope
			}
			if m := b.Meta.Rules[i]; len(m.States) > 0 {
				out.States = m.States
			}
			if m := b.Meta.Rules[i]; len(m.Events) > 0 {
				out.Events = m.Events
			}
		}
		if out.States == nil {
			out.States = make([]string, r.NumStates)
			for s := range out.States {
				out.States[s] = fmt.Sprintf("state%d", s)
			}
		}
		if out.Events == nil {
			out.Events = make([]string, r.NumEvents)
			for e := range out.Events {
				out.Events[e] = fmt.Sprintf("event%d", e)
			}
		}
		var top uint32
		for s := uint32(0); s < r.NumStates; s++ {
			for e := uint32(0); e < r.NumEvents; e++ {
				j := uint64(r.TransBase) + uint64(s)*uint64(r.NumEvents) + uint64(e)
				if j >= uint64(len(b.Transitions)) {
					continue
				}
				cell := b.Transitions[j]
				top = max(top, cell.Action)
				if cell.NextState == s && cell.Action == fsm.ActionObserve {
					continue
				}
				if int(cell.NextState) >= len(out.States) || int(s) >= len(out.States) || int(e) >= len(out.Events) {
					continue
				}
				out.Transitions = append(out.Transitions, RuleTransition{
					From:     out.States[s],
					Event:    out.Events[e],
					To:       out.States[cell.NextState],
					Action:   audit.ActionName(cell.Action),
					Syscalls: bindingSyscalls(b.Bindings, uint32(i), e),
				})
			}
		}
		out.TerminalAction = audit.ActionName(top)
		rules[i] = out
	}
	return rules
}

// bindingSyscalls returns the human-readable descriptions of every binding that
// raises event e in rule, in binding order, with duplicates removed.
func bindingSyscalls(bindings []fsm.Binding, rule, event uint32) []string {
	var out []string
	seen := map[string]bool{}
	for _, bd := range bindings {
		if bd.Rule != rule || bd.Event != event {
			continue
		}
		desc := hooks.Name(bd.Hook) + bindingPredicate(bd)
		if !seen[desc] {
			seen[desc] = true
			out = append(out, desc)
		}
	}
	return out
}

// bindingPredicate renders the leading-space predicate of a binding, or "" when
// the binding matches any argument.
func bindingPredicate(bd fsm.Binding) string {
	switch bd.PathKind {
	case fsm.PathPrefix:
		return " path^=" + patternString(bd.Pattern[:])
	case fsm.PathSunPrefix:
		return " sun_path^=" + patternString(bd.Pattern[:])
	}
	if bd.ArgOp == fsm.ArgAny {
		return ""
	}
	switch bd.ArgOp {
	case fsm.ArgEq:
		return fmt.Sprintf(" arg%d == %d", bd.ArgIndex, bd.ArgValue)
	case fsm.ArgLe:
		return fmt.Sprintf(" arg%d <= %d", bd.ArgIndex, bd.ArgValue)
	case fsm.ArgMaskAny:
		return fmt.Sprintf(" arg%d & 0x%x != 0", bd.ArgIndex, bd.ArgValue)
	case fsm.ArgMaskNone:
		return fmt.Sprintf(" arg%d & 0x%x == 0", bd.ArgIndex, bd.ArgValue)
	}
	return ""
}

func patternString(p []byte) string {
	if i := bytes.IndexByte(p, 0); i >= 0 {
		p = p[:i]
	}
	return string(p)
}

// NodeName returns NODE_NAME, else the hostname.
func NodeName(getenv func(string) string) string {
	if v := getenv("NODE_NAME"); v != "" {
		return v
	}
	h, _ := os.Hostname()
	return h
}

// AdvertiseAddr returns the metrics address the backend can scrape:
// ARIGUARD_METRICS_ADVERTISE, else POD_IP with the port of metricsAddr, else metricsAddr.
func AdvertiseAddr(metricsAddr string, getenv func(string) string) string {
	if v := getenv("ARIGUARD_METRICS_ADVERTISE"); v != "" {
		return v
	}
	if ip := getenv("POD_IP"); ip != "" && metricsAddr != "" {
		if _, port, err := net.SplitHostPort(metricsAddr); err == nil {
			return net.JoinHostPort(ip, port)
		}
	}
	return metricsAddr
}
