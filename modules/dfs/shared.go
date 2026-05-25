// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package dfs handles git-dfs JSON pointer files. The pointed-to bytes live on
// a separate xet-server, not in gitea storage. Pointer format matches
// crates/git-dfs/src/pointer.rs.
package dfs

type Pointer struct {
	Hash     string `json:"hash"`
	FileSize int64  `json:"file_size"`
	// Empty when the client didn't compute one; treat as "unknown", not "zero".
	Sha256 string `json:"sha256,omitempty"`
}
