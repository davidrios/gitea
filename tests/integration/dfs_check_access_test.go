// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/dfs"
	"code.gitea.io/gitea/services/lfs"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDFSCheckAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const expectedURL = "https://cas.example.test"
	jwtSecret := []byte("checkaccess-test-secret-32-byte!")

	repo1, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", "repo1")
	require.NoError(t, err)
	repo2, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", "repo2")
	require.NoError(t, err)

	withDFS := func() func() {
		stop1 := test.MockVariableValue(&setting.DFS.Enabled, true)
		stop2 := test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)
		stop3 := test.MockVariableValue(&setting.LFS.JWTSecretBytes, jwtSecret)
		stop4 := test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)
		return func() { stop4(); stop3(); stop2(); stop1() }
	}

	mintFor := func(t *testing.T, userID, repoID int64, op string) string {
		t.Helper()
		defer withDFS()()
		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Op: op, UserID: userID, RepoID: repoID,
		})
		require.NoError(t, err)
		return token
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

	user2ReadRepo1 := mintFor(t, 2, repo1.ID, "download")
	user2WriteRepo2 := mintFor(t, 2, repo2.ID, "upload")

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, false)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "read"))
		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("Read JWT on the repo it was minted for returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "read"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Write JWT on the private repo it was minted for returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2WriteRepo2, "user2/repo2", "write"))
		require.Equal(t, http.StatusOK, resp.StatusCode)
		var got dfs.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("JWT bound to a different repo is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2ReadRepo1, "user2/repo2", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Read-scoped JWT cannot be replayed as write", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "write"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("Bad scope returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "admin"))
		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("Bad repo_id returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withDFS()()

		resp := post(t, body(user2ReadRepo1, "no-slash-here", "read"))
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

		resp := post(t, body(user2ReadRepo1, "user2/does-not-exist", "read"))
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	})

	t.Run("Expired JWT is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, jwtSecret)()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, -time.Minute)()

		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Op: "download", UserID: 2, RepoID: repo1.ID,
		})
		require.NoError(t, err)

		resp := post(t, body(token, "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})

	t.Run("JWT minted with a different secret is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		stop1 := test.MockVariableValue(&setting.DFS.Enabled, true)
		stop2 := test.MockVariableValue(&setting.DFS.ServerURL, expectedURL)
		stop3 := test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("rotated-secret-32-bytes-xxxxxxxx"))
		stop4 := test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)
		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Op: "download", UserID: 2, RepoID: repo1.ID,
		})
		require.NoError(t, err)
		stop4()
		stop3()
		stop2()
		stop1()

		defer withDFS()() // restore canonical jwtSecret

		resp := post(t, body(token, "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	})
}
