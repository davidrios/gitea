// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"testing"

	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/bale"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaleDiscovery(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const expectedURL = "https://cas.example.test"

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, false)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo1.git/info/bale")
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Public repo returns server URL", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo1.git/info/bale")
		resp := MakeRequest(t, req, http.StatusOK)

		var got bale.DiscoveryResponse
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &got))
		assert.Equal(t, expectedURL, got.ServerURL)
	})

	t.Run("Path without .git suffix also works", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo1/info/bale")
		MakeRequest(t, req, http.StatusOK)
	})

	t.Run("Private repo without auth returns 404", func(t *testing.T) {
		// 404 not 403 — must not leak existence of private repos.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo2.git/info/bale")
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Private repo with owner session returns server URL", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		session := loginUser(t, "user2")
		req := NewRequest(t, "GET", "/user2/repo2.git/info/bale")
		resp := session.MakeRequest(t, req, http.StatusOK)

		var got bale.DiscoveryResponse
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &got))
		assert.Equal(t, expectedURL, got.ServerURL)
	})

	t.Run("Nonexistent repo returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/does-not-exist.git/info/bale")
		MakeRequest(t, req, http.StatusNotFound)
	})
}
