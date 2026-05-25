// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"testing"

	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/dfs"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercises /{owner}/{repo}.git/info/dfs, the URL-discovery endpoint that
// lets a git-dfs client find its xet-server without a hard-coded config.
func TestDFSDiscovery(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const expectedURL = "https://cas.example.test"

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, false)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo1.git/info/dfs")
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Public repo returns server URL", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo1.git/info/dfs")
		resp := MakeRequest(t, req, http.StatusOK)

		var got dfs.DiscoveryResponse
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &got))
		assert.Equal(t, expectedURL, got.ServerURL)
	})

	t.Run("Path without .git suffix also works", func(t *testing.T) {
		// git-dfs may probe both. Gitea's route matches `{reponame}` and
		// trims `.git` server-side, so both must resolve to the same repo.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo1/info/dfs")
		MakeRequest(t, req, http.StatusOK)
	})

	t.Run("Private repo without auth returns 404", func(t *testing.T) {
		// Anonymous probes must not be able to tell whether a private repo
		// exists — same shape as other gitea repo endpoints.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/repo2.git/info/dfs")
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Private repo with owner session returns server URL", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		session := loginUser(t, "user2")
		req := NewRequest(t, "GET", "/user2/repo2.git/info/dfs")
		resp := session.MakeRequest(t, req, http.StatusOK)

		var got dfs.DiscoveryResponse
		require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &got))
		assert.Equal(t, expectedURL, got.ServerURL)
	})

	t.Run("Nonexistent repo returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		req := NewRequest(t, "GET", "/user2/does-not-exist.git/info/dfs")
		MakeRequest(t, req, http.StatusNotFound)
	})
}
