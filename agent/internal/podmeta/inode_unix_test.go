//go:build unix

package podmeta

import (
	"io/fs"
	"testing"
	"time"
)

type noStat struct{}

func (noStat) Name() string       { return "x" }
func (noStat) Size() int64        { return 0 }
func (noStat) Mode() fs.FileMode  { return fs.ModeDir }
func (noStat) ModTime() time.Time { return time.Time{} }
func (noStat) IsDir() bool        { return true }
func (noStat) Sys() any           { return nil }

func TestInodeWithoutStat(t *testing.T) {
	if ino, ok := inode(noStat{}); ok || ino != 0 {
		t.Errorf("inode = %d, %v, want 0, false", ino, ok)
	}
}
