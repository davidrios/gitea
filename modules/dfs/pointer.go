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
	// Real pointers are ~150 bytes; anything larger is not a pointer. Matches
	// POINTER_MAX_BYTES in crates/git-dfs/src/pointer.rs.
	MetaFileMaxSize = 4096

	// Cheap pre-check before JSON parsing.
	MetaFileSentinel = `"hash"`
)

var (
	ErrMissingSentinel  = errors.New("content lacks the DFS pointer sentinel")
	ErrInvalidStructure = errors.New("content has an invalid DFS pointer structure")
	ErrTooLarge         = fmt.Errorf("input exceeds DFS pointer size cap of %d bytes", MetaFileMaxSize)
)

var hexPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func ReadPointer(r io.Reader) (Pointer, error) {
	buf := make([]byte, MetaFileMaxSize)
	n, err := util.ReadAtMost(r, buf)
	if err != nil {
		return Pointer{}, err
	}
	return ReadPointerFromBuffer(buf[:n])
}

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

func (p Pointer) LogString() string {
	if p.Hash == "" && p.FileSize == 0 {
		return "<DFSPointer empty>"
	}
	return fmt.Sprintf("<DFSPointer %s:%d>", p.Hash, p.FileSize)
}
