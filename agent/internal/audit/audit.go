// Package audit drains the kernel ring buffer and streams events upstream.
package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"strconv"

	"github.com/CosminMilica/statewall/agent/internal/hooks"
	"github.com/CosminMilica/statewall/pkg/fsm"
)

// RecordSize is the wire size of fsm.AuditRecord.
const RecordSize = 40

var stateNames = [...]string{
	fsm.StateNormal:           "normal",
	fsm.StateSuspicious:       "suspicious",
	fsm.StateEscalating:       "escalating",
	fsm.StateBreakoutImminent: "breakout_imminent",
	fsm.StateCompromised:      "compromised",
}

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

// StateName returns the state name, or the decimal value if unknown.
func StateName(s uint32) string { return lookup(stateNames[:], s) }

// ActionName returns the action name, or the decimal value if unknown.
func ActionName(a uint32) string { return lookup(actionNames[:], a) }

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
	TsNs     uint64 `json:"ts_ns"`
	CgroupID uint64 `json:"cgroup_id"`
	Pid      uint32 `json:"pid"`
	Hook     string `json:"hook"`
	Event    uint32 `json:"event"`
	From     string `json:"from"`
	To       string `json:"to"`
	Action   string `json:"action"`
}

// NewEvent converts a kernel record to its JSON form.
func NewEvent(r fsm.AuditRecord) Event {
	return Event{
		TsNs:     r.TsNs,
		CgroupID: r.CgroupID,
		Pid:      r.Pid,
		Hook:     hooks.Name(r.Hook),
		Event:    r.Event,
		From:     StateName(r.FromState),
		To:       StateName(r.ToState),
		Action:   ActionName(r.Action),
	}
}

// WriteLine writes r as one JSON object followed by a newline.
func WriteLine(w io.Writer, r fsm.AuditRecord) error {
	line, err := json.Marshal(NewEvent(r))
	if err != nil {
		return err
	}
	_, err = w.Write(append(line, '\n'))
	return err
}
