// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const samplePointer = `{
  "hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "file_size": 12345,
  "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
}
`

func TestReadPointerFromBuffer_HappyPath(t *testing.T) {
	p, err := ReadPointerFromBuffer([]byte(samplePointer))
	require.NoError(t, err)
	assert.Equal(t, strings.Repeat("a", 64), p.Hash)
	assert.EqualValues(t, 12345, p.FileSize)
	assert.Equal(t, strings.Repeat("b", 64), p.Sha256)
	assert.True(t, p.IsValid())
}

func TestReadPointerFromBuffer_Sha256Optional(t *testing.T) {
	const noSha = `{"hash":"` +
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `","file_size":7}`
	p, err := ReadPointerFromBuffer([]byte(noSha))
	require.NoError(t, err)
	assert.Empty(t, p.Sha256)
	assert.True(t, p.IsValid())
}

func TestReadPointerFromBuffer_NoSentinel(t *testing.T) {
	_, err := ReadPointerFromBuffer([]byte("hello world\n"))
	assert.ErrorIs(t, err, ErrMissingSentinel)
}

func TestReadPointerFromBuffer_TooLarge(t *testing.T) {
	huge := bytes.Repeat([]byte("a"), MetaFileMaxSize+1)
	_, err := ReadPointerFromBuffer(huge)
	assert.ErrorIs(t, err, ErrTooLarge)
}

func TestReadPointerFromBuffer_BadHash(t *testing.T) {
	bad := `{"hash":"` + strings.Repeat("a", 63) + `","file_size":1}`
	_, err := ReadPointerFromBuffer([]byte(bad))
	assert.ErrorIs(t, err, ErrInvalidStructure)
}

func TestReadPointerFromBuffer_NegativeSize(t *testing.T) {
	bad := `{"hash":"` + strings.Repeat("a", 64) + `","file_size":-1}`
	_, err := ReadPointerFromBuffer([]byte(bad))
	assert.ErrorIs(t, err, ErrInvalidStructure)
}

func TestReadPointerFromBuffer_MalformedJSON(t *testing.T) {
	bad := `{"hash": broken`
	_, err := ReadPointerFromBuffer([]byte(bad))
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrMissingSentinel))
	assert.False(t, errors.Is(err, ErrInvalidStructure))
}

func TestReadPointer_FromStream(t *testing.T) {
	p, err := ReadPointer(strings.NewReader(samplePointer))
	require.NoError(t, err)
	assert.True(t, p.IsValid())
}

func TestReadPointer_LargeBlobIsNotAPointer(t *testing.T) {
	body := samplePointer + strings.Repeat("x", MetaFileMaxSize*2)
	_, err := ReadPointer(strings.NewReader(body))
	require.Error(t, err)
}

func TestIsValid_EmptyPointer(t *testing.T) {
	assert.False(t, Pointer{}.IsValid())
}

func TestLogString(t *testing.T) {
	assert.Equal(t, "<DFSPointer empty>", Pointer{}.LogString())
	p := Pointer{Hash: strings.Repeat("a", 64), FileSize: 9}
	assert.Contains(t, p.LogString(), "<DFSPointer ")
	assert.Contains(t, p.LogString(), ":9>")
}
