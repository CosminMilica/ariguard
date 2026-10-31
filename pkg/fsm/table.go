package fsm

import (
	"encoding/binary"
	"fmt"
)

// Transition-table binary format v1 (little-endian).
const (
	tableMagic      uint32 = 0x53544254 // "STBT"
	tableVersion    uint32 = 1
	tableHeaderSize        = 16
	entrySize              = 8
)

// Table is a dense (state, event) -> Transition lookup in row-major order.
type Table struct {
	NumStates   uint32
	NumEvents   uint32
	Transitions []Transition // len == NumStates*NumEvents, index = state*NumEvents + event
}

// At returns the transition for (state, event).
func (t *Table) At(state, event uint32) Transition {
	return t.Transitions[state*t.NumEvents+event]
}

// Marshal encodes the table into the v1 binary format.
func (t *Table) Marshal() ([]byte, error) {
	want := int(t.NumStates) * int(t.NumEvents)
	if len(t.Transitions) != want {
		return nil, fmt.Errorf("fsm: transition count %d != num_states*num_events %d", len(t.Transitions), want)
	}
	buf := make([]byte, tableHeaderSize+want*entrySize)
	binary.LittleEndian.PutUint32(buf[0:], tableMagic)
	binary.LittleEndian.PutUint32(buf[4:], tableVersion)
	binary.LittleEndian.PutUint32(buf[8:], t.NumStates)
	binary.LittleEndian.PutUint32(buf[12:], t.NumEvents)
	off := tableHeaderSize
	for _, tr := range t.Transitions {
		binary.LittleEndian.PutUint32(buf[off:], tr.NextState)
		binary.LittleEndian.PutUint32(buf[off+4:], tr.Action)
		off += entrySize
	}
	return buf, nil
}

// Unmarshal decodes a table from the v1 binary format.
func Unmarshal(data []byte) (*Table, error) {
	if len(data) < tableHeaderSize {
		return nil, fmt.Errorf("fsm: data too short for header: %d bytes", len(data))
	}
	magic := binary.LittleEndian.Uint32(data[0:])
	if magic != tableMagic {
		return nil, fmt.Errorf("fsm: bad magic 0x%08x", magic)
	}
	version := binary.LittleEndian.Uint32(data[4:])
	if version != tableVersion {
		return nil, fmt.Errorf("fsm: unsupported version %d", version)
	}
	t := &Table{
		NumStates: binary.LittleEndian.Uint32(data[8:]),
		NumEvents: binary.LittleEndian.Uint32(data[12:]),
	}
	count := int(t.NumStates) * int(t.NumEvents)
	if len(data) != tableHeaderSize+count*entrySize {
		return nil, fmt.Errorf("fsm: body size %d != expected %d", len(data)-tableHeaderSize, count*entrySize)
	}
	t.Transitions = make([]Transition, count)
	off := tableHeaderSize
	for i := range t.Transitions {
		t.Transitions[i] = Transition{
			NextState: binary.LittleEndian.Uint32(data[off:]),
			Action:    binary.LittleEndian.Uint32(data[off+4:]),
		}
		off += entrySize
	}
	return t, nil
}
