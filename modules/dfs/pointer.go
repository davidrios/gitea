// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"code.gitea.io/gitea/modules/util"
)

const (
	// MetaFileMaxSize is the soft cap on a DFS pointer file size. Real pointers
	// are ~150 bytes; anything larger is almost certainly a non-pointer blob.
	// Matches `POINTER_MAX_BYTES` in `crates/git-dfs/src/pointer.rs`.
	MetaFileMaxSize = 4096

	// MetaFileSentinel is the cheap pre-check before JSON parsing — DFS
	// pointers always contain this key near the start. Avoids running
	// json.Unmarshal on every small text blob.
	MetaFileSentinel = `"hash"`
)

var (
	// ErrMissingSentinel occurs when a buffer doesn't contain the DFS pointer
	// sentinel and so isn't worth parsing as JSON.
	ErrMissingSentinel = errors.New("content lacks the DFS pointer sentinel")

	// ErrInvalidStructure occurs when the JSON parses but the resulting
	// pointer fields fail the basic shape checks.
	ErrInvalidStructure = errors.New("content has an invalid DFS pointer structure")

	// ErrTooLarge occurs when input exceeds MetaFileMaxSize.
	ErrTooLarge = fmt.Errorf("input exceeds DFS pointer size cap of %d bytes", MetaFileMaxSize)
)

// hexPattern matches a 64-char lowercase hex string (xet hashes and sha256
// OIDs are both 32 bytes → 64 hex chars).
var hexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// ReadPointer reads up to MetaFileMaxSize bytes from r and tries to parse the
// result as a DFS pointer.
func ReadPointer(r io.Reader) (Pointer, error) {
	buf := make([]byte, MetaFileMaxSize)
	n, err := util.ReadAtMost(r, buf)
	if err != nil {
		return Pointer{}, err
	}
	return ReadPointerFromBuffer(buf[:n])
}

// ReadPointerFromBuffer parses buf as a DFS pointer. Returns ErrMissingSentinel
// for non-pointer content (cheap rejection), ErrTooLarge if buf overflows the
// cap, or a JSON / shape error otherwise.
func ReadPointerFromBuffer(buf []byte) (Pointer, error) {
	if len(buf) > MetaFileMaxSize {
		return Pointer{}, ErrTooLarge
	}
	if !bytes.Contains(buf, []byte(MetaFileSentinel)) {
		return Pointer{}, ErrMissingSentinel
	}
	var p Pointer
	if err := json.Unmarshal(bytes.TrimSpace(buf), &p); err != nil {
		return Pointer{}, err
	}
	if !p.IsValid() {
		return Pointer{}, ErrInvalidStructure
	}
	return p, nil
}

// IsValid checks the pointer's shape without touching the network — hash and
// (when present) sha256 must be 64-char lowercase hex, file_size must be
// non-negative.
func (p Pointer) IsValid() bool {
	if !hexPattern.MatchString(p.Hash) {
		return false
	}
	if p.FileSize < 0 {
		return false
	}
	if p.Sha256 != "" && !hexPattern.MatchString(p.Sha256) {
		return false
	}
	return true
}

// LogString matches the `fmt.Stringer` style used by lfs.Pointer for log lines.
func (p Pointer) LogString() string {
	if p.Hash == "" && p.FileSize == 0 {
		return "<DFSPointer empty>"
	}
	return fmt.Sprintf("<DFSPointer %s:%d>", p.Hash, p.FileSize)
}
