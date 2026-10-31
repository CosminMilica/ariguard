//go:build unix

package podmeta

import (
	"io/fs"
	"syscall"
)

// inode is the cgroup v2 id of a cgroup directory.
func inode(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Ino), true
}
