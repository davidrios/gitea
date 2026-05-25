// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"encoding/base64"
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

// Exercises POST /<owner>/<repo>.git/info/dfs/authenticate — the HTTPS
// analog of the SSH `git-dfs-authenticate` command. The user's gitea
// credentials are presented via Basic auth; the response carries a
// short-lived JWT scoped to that user. The user's password must never
// leave gitea; xet-server only ever sees the JWT.
func TestDFSAuthenticateHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const xetURL = "https://cas.example.test"
	const userPassword = "password" // matches the default password for fixture users

	basic := func(user, pass string) string {
		return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	}

	post := func(t *testing.T, path, authz string) *http.Response {
		t.Helper()
		req := NewRequest(t, "POST", path)
		if authz != "" {
			req.Header.Set("Authorization", authz)
		}
		return MakeRequest(t, req, NoExpectedStatus).Result()
	}

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, false)()

		resp := post(t, "/user2/repo1.git/info/dfs/authenticate?op=download", basic("user2", userPassword))
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Real password mints a JWT", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, 5*time.Minute)()

		resp := post(t, "/user2/repo1.git/info/dfs/authenticate?op=download", basic("user2", userPassword))
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var got dfs.AuthenticateResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, xetURL, got.Href)
		assert.NotEmpty(t, got.ExpiresAt)
		assert.Contains(t, got.Header["Authorization"], "Bearer ")

		// The minted JWT must round-trip through check_access (same user).
		bearer := got.Header["Authorization"][len("Bearer "):]
		userID, err := dfs.ParseEphemeralBearer(bearer)
		require.NoError(t, err)
		assert.EqualValues(t, 2, userID, "user2's fixture ID is 2")
	})

	t.Run("Missing auth returns 401 with Basic challenge", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		resp := post(t, "/user2/repo1.git/info/dfs/authenticate?op=download", "")
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
		assert.Contains(t, resp.Header.Get("WWW-Authenticate"), "Basic")
	})

	t.Run("Wrong password returns 401", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		resp := post(t, "/user2/repo1.git/info/dfs/authenticate?op=download", basic("user2", "nope"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Bad op returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		resp := post(t, "/user2/repo1.git/info/dfs/authenticate?op=admin", basic("user2", userPassword))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Authenticated but write on unrelated private repo is 403", func(t *testing.T) {
		// user10/repo6 is private, owned by user10. user2 has no access.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, 5*time.Minute)()

		resp := post(t, "/user10/repo6.git/info/dfs/authenticate?op=upload", basic("user2", userPassword))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})
}
