// Package learnring is the linux-only ring-buffer glue backing learn-mode (AG_LEARN, F11): it reads
// raw LearnRecords and feeds them to a learn.Assembler. Like audit/ringbuf and podsync/podmap it has
// no unit tests (it needs a live kernel ring) and is covered by ci-kernel, not the host coverage gate.
package learnring
