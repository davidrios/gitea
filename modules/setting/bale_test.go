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
		Bale.InternalServerURL = ""
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
		// InternalServerURL defaults to the public URL when unset.
		assert.Equal(t, "https://cas.example.test", Bale.InternalServerURL)
	})

	t.Run("internal URL kept separate from public URL", func(t *testing.T) {
		defer resetBale()
		cfg, err := NewConfigProviderFromData(`
[bale]
ENABLED = true
SERVER_URL = https://cas.example.test/
INTERNAL_SERVER_URL = http://bale.internal:8080/
`)
		require.NoError(t, err)
		loadBaleFrom(cfg)
		assert.True(t, Bale.Enabled)
		assert.Equal(t, "https://cas.example.test", Bale.ServerURL)
		assert.Equal(t, "http://bale.internal:8080", Bale.InternalServerURL)
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
