//go:build linux

package learn

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	cringbuf "github.com/cilium/ebpf/ringbuf"

	"github.com/CosminMilica/ariguard/pkg/fsm"
)

// Drain reads AG_LEARN and feeds each record to the assembler until ctx is done. It mirrors
// audit/ringbuf.Stream: a reader closed on ctx cancellation, malformed samples dropped.
func Drain(ctx context.Context, m *ebpf.Map, a *Assembler, log *slog.Logger) error {
	rd, err := cringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("open learn ring buffer: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = rd.Close() })
	defer stop()
	defer func() { _ = rd.Close() }()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, cringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read learn ring buffer: %w", err)
		}
		r, err := decode(rec.RawSample)
		if err != nil {
			log.Warn("drop learn sample", "err", err)
			continue
		}
		a.Add(ctx, r)
	}
}

// decode reads a fsm.LearnRecord off the wire (native endianness, like the audit decoder).
func decode(raw []byte) (Record, error) {
	var lr fsm.LearnRecord
	if len(raw) < int(binary.Size(&lr)) {
		return Record{}, fmt.Errorf("short learn sample: %d bytes", len(raw))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &lr); err != nil {
		return Record{}, err
	}
	return Record{CgroupID: lr.CgroupID, TsNs: lr.TsNs, Pid: lr.Pid, Hook: lr.Hook}, nil
}
