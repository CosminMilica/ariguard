//go:build linux

package audit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/CosminMilica/statewall/agent/internal/podmeta"
)

// Stream reads SW_AUDIT and writes one JSON line per record to w until ctx is done.
// Names are read per record, so a reload takes effect on the next line; pods may be nil.
func Stream(ctx context.Context, m *ebpf.Map, w io.Writer, names *Names, pods Pods, log *slog.Logger) error {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("open audit ring buffer: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { _ = rd.Close() })
	defer stop()
	defer func() { _ = rd.Close() }()

	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read audit ring buffer: %w", err)
		}
		r, err := Decode(rec.RawSample)
		if err != nil {
			log.Warn("drop audit sample", "err", err)
			continue
		}
		var pod podmeta.Info
		if pods != nil {
			pod = pods.Lookup(ctx, r.CgroupID)
		}
		if err := WriteLine(w, NewEvent(r, names.Load(), pod)); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}
}
