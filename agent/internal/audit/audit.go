// Package audit drains the kernel ring buffer and streams events upstream.
package audit

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"

	"github.com/CosminMilica/ariguard/agent/internal/hooks"
	"github.com/CosminMilica/ariguard/agent/internal/podmeta"
	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// RecordSize is the wire size of fsm.AuditRecord.
const RecordSize = 72

var actionNames = [...]string{
	fsm.ActionObserve:  "observe",
	fsm.ActionThrottle: "throttle",
	fsm.ActionDeny:     "deny",
	fsm.ActionKill:     "kill",
}

func lookup(table []string, v uint32) string {
	if int(v) < len(table) {
		return table[v]
	}
	return strconv.FormatUint(uint64(v), 10)
}

// ActionName returns the action name, or the decimal value if unknown.
func ActionName(a uint32) string { return lookup(actionNames[:], a) }

// Names holds the bundle metadata of the active policy; safe for concurrent use.
type Names struct {
	meta  atomic.Pointer[fsm.Meta]
	comms CommCache
}

// SetComm records the last-seen process command of a cgroup.
func (n *Names) SetComm(cgroup uint64, comm string) {
	if n != nil {
		n.comms.Set(cgroup, comm)
	}
}

// Comm returns the last-seen process command of a cgroup.
func (n *Names) Comm(cgroup uint64) (string, bool) {
	if n == nil {
		return "", false
	}
	return n.comms.Get(cgroup)
}

// Store publishes the names of a newly applied bundle.
func (n *Names) Store(m fsm.Meta) { n.meta.Store(&m) }

// Load returns the current names; nil before the first Store.
func (n *Names) Load() *fsm.Meta {
	if n == nil {
		return nil
	}
	return n.meta.Load()
}

// Pods resolves a cgroup id to pod metadata.
type Pods interface {
	Lookup(ctx context.Context, cgroupID uint64) podmeta.Info
	// IsPod reports whether the cgroup belongs to a Kubernetes pod container.
	IsPod(cgroupID uint64) bool
}

// Decode parses one little-endian ring buffer sample.
func Decode(sample []byte) (fsm.AuditRecord, error) {
	var r fsm.AuditRecord
	if len(sample) < RecordSize {
		return r, fmt.Errorf("audit sample too short: %d bytes, want %d", len(sample), RecordSize)
	}
	err := binary.Read(bytes.NewReader(sample[:RecordSize]), binary.LittleEndian, &r)
	return r, err
}

// Event is the JSON line form of an audit record. Field names are consumed by the evaluation scripts.
type Event struct {
	TsNs      uint64 `json:"ts_ns"`
	CgroupID  uint64 `json:"cgroup_id"`
	Pid       uint32 `json:"pid"`
	Ppid      uint32 `json:"ppid"`
	Comm      string `json:"comm"`
	Hook      string `json:"hook"`
	Rule      string `json:"rule"`
	Event     string `json:"event"`
	From      string `json:"from"`
	To        string `json:"to"`
	Action    string `json:"action"`
	Enforced  bool   `json:"enforced"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container"`
	Image     string `json:"image"`
	ImageID   string `json:"image_id"`
}

func number(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func name(names []string, v uint32) string {
	if int(v) < len(names) && names[v] != "" {
		return names[v]
	}
	return number(v)
}

// NewEvent converts a kernel record to its JSON form; meta may be nil.
func NewEvent(r fsm.AuditRecord, meta *fsm.Meta, pod podmeta.Info) Event {
	e := Event{
		TsNs:      r.TsNs,
		CgroupID:  r.CgroupID,
		Pid:       r.Pid,
		Ppid:      r.Ppid,
		Comm:      comm(r.Comm),
		Hook:      hooks.Name(r.Hook),
		Rule:      number(r.Rule),
		Event:     number(r.Event),
		From:      number(r.FromState),
		To:        number(r.ToState),
		Action:    ActionName(r.Action),
		Enforced:  r.Enforced != 0,
		Namespace: pod.Namespace,
		Pod:       pod.Pod,
		Container: pod.Container,
		Image:     pod.Image,
		ImageID:   pod.ImageID,
	}
	if meta != nil && int(r.Rule) < len(meta.Rules) {
		rm := meta.Rules[r.Rule]
		if rm.Name != "" {
			e.Rule = rm.Name
		}
		e.Event = name(rm.Events, r.Event)
		e.From = name(rm.States, r.FromState)
		e.To = name(rm.States, r.ToState)
	}
	return e
}

func comm(c [fsm.CommLen]byte) string {
	if i := bytes.IndexByte(c[:], 0); i >= 0 {
		return string(c[:i])
	}
	return string(c[:])
}

// WriteLine writes e as one JSON object followed by a newline.
func WriteLine(w io.Writer, e Event) error {
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}
