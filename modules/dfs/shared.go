// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package dfs handles git-dfs pointer files. git-dfs is a content-addressed
// alternative to LFS where pointer content is JSON and the actual bytes live
// on a separate `xet-server` rather than in gitea's storage.
//
// Pointer format (matches `crates/git-dfs/src/pointer.rs` in the parent
// workspace and `xet_data::processing::XetFileInfo`):
//
//	{
//	  "hash": "<64-hex Xet merkle hash>",
//	  "file_size": <int64>,
//	  "sha256": "<64-hex sha256>"   // omitted when unknown
//	}
package dfs

// Pointer is a parsed git-dfs JSON pointer.
type Pointer struct {
	Hash     string `json:"hash"`
	FileSize int64  `json:"file_size"`
	// Sha256 is the sha256 of the original file content. It is omitted from
	// the pointer JSON when the client didn't compute one (e.g. streaming
	// upload before sha was finalized). Treat empty as "unknown", not "zero".
	Sha256 string `json:"sha256,omitempty"`
}
