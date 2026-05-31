// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/bale"
	"code.gitea.io/gitea/services/lfs"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaleCheckAccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const expectedURL = "https://cas.example.test"
	jwtSecret := []byte("checkaccess-test-secret-32-byte!")

	repo1, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", "repo1")
	require.NoError(t, err)
	repo2, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", "repo2")
	require.NoError(t, err)

	withBale := func() func() {
		stop1 := test.MockVariableValue(&setting.Bale.Enabled, true)
		stop2 := test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)
		stop3 := test.MockVariableValue(&setting.LFS.JWTSecretBytes, jwtSecret)
		stop4 := test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)
		return func() { stop4(); stop3(); stop2(); stop1() }
	}

	mintFor := func(t *testing.T, userID, repoID int64, op string) string {
		t.Helper()
		defer withBale()()
		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Op: op, UserID: userID, RepoID: repoID,
		})
		require.NoError(t, err)
		return token
	}

	post := func(t *testing.T, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := NewRequestWithBody(t, "POST", "/-/bale/check_access", bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
		return MakeRequest(t, req, NoExpectedStatus)
	}

	body := func(hubBearer, repoID, scope string) string {
		req := bale.CheckAccessRequest{
			HubBearer: hubBearer,
			Repo: bale.CheckAccessRepoRef{
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
		defer test.MockVariableValue(&setting.Bale.Enabled, false)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "read"))
		assert.Equal(t, http.StatusNotFound, resp.Code)
	})

	t.Run("Read JWT on the repo it was minted for returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "read"))
		require.Equal(t, http.StatusOK, resp.Code)
		var got bale.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Write JWT on the private repo it was minted for returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2WriteRepo2, "user2/repo2", "write"))
		require.Equal(t, http.StatusOK, resp.Code)
		var got bale.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
	})

	t.Run("Anonymous read JWT on a public repo returns the anonymous principal", func(t *testing.T) {
		// UserID 0 is the anonymous principal; user2/repo1 is public.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		anonReadRepo1 := mintFor(t, 0, repo1.ID, "download")
		resp := post(t, body(anonReadRepo1, "user2/repo1", "read"))
		require.Equal(t, http.StatusOK, resp.Code)
		var got bale.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, bale.AnonymousUserID, got.UserID)
	})

	t.Run("Anonymous read JWT on a private repo is rejected", func(t *testing.T) {
		// user2/repo2 is private — an anonymous principal has no read access.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		anonReadRepo2 := mintFor(t, 0, repo2.ID, "download")
		resp := post(t, body(anonReadRepo2, "user2/repo2", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Anonymous JWT cannot be used for write", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		anonReadRepo1 := mintFor(t, 0, repo1.ID, "download")
		resp := post(t, body(anonReadRepo1, "user2/repo1", "write"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("JWT bound to a different repo is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2ReadRepo1, "user2/repo2", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Read-scoped JWT cannot be replayed as write", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "write"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Bad scope returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2ReadRepo1, "user2/repo1", "admin"))
		assert.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("Bad repo_id returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2ReadRepo1, "no-slash-here", "read"))
		assert.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("Malformed JSON returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, `{"hub_bearer": "nope"`)
		assert.Equal(t, http.StatusBadRequest, resp.Code)
	})

	t.Run("Nonexistent repo returns 403", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2ReadRepo1, "user2/does-not-exist", "read"))
		assert.Equal(t, http.StatusForbidden, resp.Code)
	})

	t.Run("Expired JWT is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, jwtSecret)()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, -time.Minute)()

		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Op: "download", UserID: 2, RepoID: repo1.ID,
		})
		require.NoError(t, err)

		resp := post(t, body(token, "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("JWT minted with a different secret is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		stop1 := test.MockVariableValue(&setting.Bale.Enabled, true)
		stop2 := test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)
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

		defer withBale()() // restore canonical jwtSecret

		resp := post(t, body(token, "user2/repo1", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})
}
