//go:build !unix

package podmeta

import "io/fs"

func inode(fs.FileInfo) (uint64, bool) { return 0, false }
