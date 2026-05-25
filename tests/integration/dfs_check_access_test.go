// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net/http"
	"strings"
	"testing"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/dfs"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercises POST /-/dfs/check_access — the upstream-authz hook that
// xet-server's HttpAuthz posts to. End-to-end shape with a real gitea PAT.
func TestDFSCheckAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const expectedURL = "https://cas.example.test"

	// Mint a real PAT for user2 — that's what the git-dfs client would put
	// into git-credential and what xet-server would forward as `hub_bearer`.
	session := loginUser(t, "user2")
	user2Token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeAll)

	post := func(t *testing.T, body string) *http.Response {
		t.Helper()
		req := NewRequestWithBody(t, "POST", "/-/dfs/check_access", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		return MakeRequest(t, req, NoExpectedStatus).Result()
	}

	body := func(hubBearer, repoID, scope string) string {
		req := dfs.CheckAccessRequest{
			HubBearer: hubBearer,
			Repo: dfs.CheckAccessRepoRef{
				RepoType: "model",
				RepoID:   repoID,
				Revision: "main",
			},
			Scope: scope,
		}
		b, err := json.Marshal(req)
		require.NoError(t, err)
		return string(b)
	}

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, false)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "user2/repo1", "read"))
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Owner read on public repo returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "user2/repo1", "read"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Owner write on own private repo returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "user2/repo2", "write"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Other user's private repo returns 403", func(t *testing.T) {
		// user10/repo6 is private and owned by user10. user2 is unrelated
		// (no team membership, not an owner), so a write attempt must 403.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "user10/repo6", "write"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Unknown bearer returns 401", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		// 40-char hex but not a real token.
		resp := post(t, body(strings.Repeat("d", 40), "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Bad scope returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "user2/repo1", "admin"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Bad repo_id returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "no-slash-here", "read"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Malformed JSON returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, `{"hub_bearer": "nope"`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Ephemeral JWT bearer accepted alongside PATs", func(t *testing.T) {
		// SSH-issued ephemeral bearers must be recognized by check_access so
		// the SSH flow (git-dfs-authenticate) round-trips through the same
		// upstream-authz seam as the HTTPS PAT flow. user2's ID in the
		// integration fixtures is 2.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("integration-test-secret-32-bytes"))()
		defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, 5*time.Minute)()

		bearer, _, err := dfs.MintEphemeralBearer(2)
		require.NoError(t, err)

		resp := post(t, body(bearer, "user2/repo1", "read"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Nonexistent repo returns 403", func(t *testing.T) {
		// Treat "user authenticated but can't see this repo" uniformly as
		// 403 — the handler doesn't disclose whether the repo doesn't exist
		// or whether they merely can't see it.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2Token, "user2/does-not-exist", "read"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}
