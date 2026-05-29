// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package bale handles git-bale JSON pointer files. The pointed-to bytes live on
// a separate baleforgit-server, not in gitea storage. Pointer format matches
// crates/git-bale/src/pointer.rs.
package bale

type Pointer struct {
	Hash     string `json:"hash"`
	FileSize int64  `json:"file_size"`
	// Empty when the client didn't compute one; treat as "unknown", not "zero".
	Sha256 string `json:"sha256,omitempty"`
}
