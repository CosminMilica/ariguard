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
)

// Stream reads SW_AUDIT and writes one JSON line per record to w until ctx is done.
func Stream(ctx context.Context, m *ebpf.Map, w io.Writer, log *slog.Logger) error {
	rd, err := ringbuf.NewReader(m)
	if err != nil {
		return fmt.Errorf("open audit ring buffer: %w", err)
	}
	stop := context.AfterFunc(ctx, func() { rd.Close() })
	defer stop()
	defer rd.Close()

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
		if err := WriteLine(w, r); err != nil {
			return fmt.Errorf("write audit event: %w", err)
		}
	}
}
