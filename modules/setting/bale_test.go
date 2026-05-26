// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadBaleFrom(t *testing.T) {
	resetBale := func() {
		Bale.Enabled = false
		Bale.ServerURL = ""
	}

	t.Run("disabled when section is missing", func(t *testing.T) {
		defer resetBale()
		cfg, err := NewConfigProviderFromData(``)
		require.NoError(t, err)
		loadBaleFrom(cfg)
		assert.False(t, Bale.Enabled)
		assert.Empty(t, Bale.ServerURL)
	})

	t.Run("enabled with trailing slash trimmed", func(t *testing.T) {
		defer resetBale()
		cfg, err := NewConfigProviderFromData(`
[bale]
ENABLED = true
SERVER_URL = https://cas.example.test/
`)
		require.NoError(t, err)
		loadBaleFrom(cfg)
		assert.True(t, Bale.Enabled)
		assert.Equal(t, "https://cas.example.test", Bale.ServerURL)
	})

	t.Run("force-disabled when URL is empty", func(t *testing.T) {
		defer resetBale()
		cfg, err := NewConfigProviderFromData(`
[bale]
ENABLED = true
`)
		require.NoError(t, err)
		loadBaleFrom(cfg)
		assert.False(t, Bale.Enabled)
	})
}
