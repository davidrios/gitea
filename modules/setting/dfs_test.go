// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadDFSFrom(t *testing.T) {
	resetDFS := func() {
		DFS.Enabled = false
		DFS.ServerURL = ""
	}

	t.Run("disabled when section is missing", func(t *testing.T) {
		defer resetDFS()
		cfg, err := NewConfigProviderFromData(``)
		require.NoError(t, err)
		loadDFSFrom(cfg)
		assert.False(t, DFS.Enabled)
		assert.Empty(t, DFS.ServerURL)
	})

	t.Run("enabled with trailing slash trimmed", func(t *testing.T) {
		defer resetDFS()
		cfg, err := NewConfigProviderFromData(`
[dfs]
ENABLED = true
SERVER_URL = https://cas.example.test/
`)
		require.NoError(t, err)
		loadDFSFrom(cfg)
		assert.True(t, DFS.Enabled)
		assert.Equal(t, "https://cas.example.test", DFS.ServerURL)
	})

	t.Run("force-disabled when URL is empty", func(t *testing.T) {
		// Without a server URL the discovery endpoint has nothing to hand
		// back. Refuse to come up half-configured.
		defer resetDFS()
		cfg, err := NewConfigProviderFromData(`
[dfs]
ENABLED = true
`)
		require.NoError(t, err)
		loadDFSFrom(cfg)
		assert.False(t, DFS.Enabled)
	})
}
