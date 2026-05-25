// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/dfs"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Exercises POST /-/dfs/check_access — the upstream-authz hook that
// xet-server's HttpAuthz posts to. The contract is that `hub_bearer`
// carries an ephemeral JWT minted by gitea (HTTPS authenticate or SSH
// git-dfs-authenticate); the client trades any long-lived credential
// for a short-lived JWT inside gitea before reaching xet-server.
func TestDFSCheckAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const expectedURL = "https://cas.example.test"
	jwtSecret := []byte("checkaccess-test-secret-32-byte!")

	withDFS := func() func() {
		stop1 := test.MockVariableValue(&setting.DFS.Enabled, true)
		stop2 := test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)
		stop3 := test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, jwtSecret)
		stop4 := test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, 5*time.Minute)
		return func() { stop4(); stop3(); stop2(); stop1() }
	}

	// user2's fixture ID is 2 — bake the JWT we'd otherwise mint via the
	// SSH or HTTPS authenticate handlers. Helper requires DFS settings to
	// be mocked first.
	mintFor := func(t *testing.T, userID int64) string {
		t.Helper()
		defer withDFS()()
		bearer, _, err := dfs.MintEphemeralBearer(userID)
		require.NoError(t, err)
		return bearer
	}

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

	user2JWT := mintFor(t, 2)

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, false)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2JWT, "user2/repo1", "read"))
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Ephemeral JWT on public repo returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2JWT, "user2/repo1", "read"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Ephemeral JWT for write on own private repo returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2JWT, "user2/repo2", "write"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Ephemeral JWT can't reach an unrelated private repo", func(t *testing.T) {
		// user10/repo6 is private and owned by user10. user2's JWT is
		// authenticated, just lacks visibility → 403 (handler hides
		// "doesn't exist" vs "no access" uniformly).
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2JWT, "user10/repo6", "write"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Bad scope returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2JWT, "user2/repo1", "admin"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Bad repo_id returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2JWT, "no-slash-here", "read"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Malformed JSON returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, `{"hub_bearer": "nope"`)
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Nonexistent repo returns 403", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2JWT, "user2/does-not-exist", "read"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Expired JWT is rejected", func(t *testing.T) {
		// Mint a token with a TTL that's already elapsed.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, jwtSecret)()
		defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, -time.Minute)()

		bearer, _, err := dfs.MintEphemeralBearer(2)
		require.NoError(t, err)
		// Switch TTL back to positive — we want check_access to reject the
		// already-expired token, not to fail at mint validation.
		// (MintEphemeralBearer doesn't validate exp itself.)

		resp := post(t, body(bearer, "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("JWT minted with a different secret is rejected", func(t *testing.T) {
		// Simulates a stolen JWT from an old gitea install — rotated
		// secret invalidates outstanding bearers immediately.
		defer tests.PrintCurrentTest(t)()
		stop1 := test.MockVariableValue(&setting.DFS.Enabled, true)
		stop2 := test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)
		stop3 := test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("rotated-secret-32-bytes-xxxxxxxx"))
		stop4 := test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, 5*time.Minute)
		bearer, _, err := dfs.MintEphemeralBearer(2)
		require.NoError(t, err)
		stop4()
		stop3()
		stop2()
		stop1()

		defer withDFS()() // restore the canonical jwtSecret

		resp := post(t, body(bearer, "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
