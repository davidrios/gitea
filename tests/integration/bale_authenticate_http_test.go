// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	git_model "code.gitea.io/gitea/models/git"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaleAuthenticateHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const xetURL = "https://cas.example.test"

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, false)()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Real password mints a JWT", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download").AddBasicAuth("user2")
		resp := MakeRequest(t, req, http.StatusOK)

		var got git_model.LFSTokenResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, xetURL, got.Href)
		assert.True(t, strings.HasPrefix(got.Header["Authorization"], "Bearer "))
	})

	t.Run("Anonymous download on a public repo mints a JWT", func(t *testing.T) {
		// user2/repo1 is public, so a credential-less download is an anonymous read.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download")
		resp := MakeRequest(t, req, http.StatusOK)

		var got git_model.LFSTokenResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, xetURL, got.Href)
		assert.True(t, strings.HasPrefix(got.Header["Authorization"], "Bearer "))
	})

	t.Run("Anonymous download on a private repo returns 401 with Basic challenge", func(t *testing.T) {
		// user2/repo2 is private; an anonymous read must be challenged, not granted.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo2.git/info/bale/authenticate?op=download")
		resp := MakeRequest(t, req, http.StatusUnauthorized)
		assert.Contains(t, resp.Header().Get("WWW-Authenticate"), "Basic")
	})

	t.Run("Anonymous download on a missing repo is challenged like a private one", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/does-not-exist.git/info/bale/authenticate?op=download")
		missing := MakeRequest(t, req, http.StatusUnauthorized)
		req = NewRequest(t, "POST", "/user2/repo2.git/info/bale/authenticate?op=download")
		private := MakeRequest(t, req, http.StatusUnauthorized)
		assert.Equal(t, private.Header().Get("WWW-Authenticate"), missing.Header().Get("WWW-Authenticate"))
		assert.Equal(t, private.Body.String(), missing.Body.String())
	})

	t.Run("Anonymous download is refused when sign-in is required", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.Service.RequireSignInViewStrict, true)()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download")
		resp := MakeRequest(t, req, http.StatusUnauthorized)
		assert.Contains(t, resp.Header().Get("WWW-Authenticate"), "Basic")
		req = NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusOK)
	})

	t.Run("Anonymous upload is never granted", func(t *testing.T) {
		// Even on a public repo, a credential-less upload is rejected with 401.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=upload")
		resp := MakeRequest(t, req, http.StatusUnauthorized)
		assert.Contains(t, resp.Header().Get("WWW-Authenticate"), "Basic")
	})

	t.Run("Wrong password returns 401", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download").AddBasicAuth("user2", "nope")
		MakeRequest(t, req, http.StatusUnauthorized)
	})

	t.Run("Bad op returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=admin").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusBadRequest)
	})

	withBale := func() func() {
		stop1 := test.MockVariableValue(&setting.Bale.Enabled, true)
		stop2 := test.MockVariableValue(&setting.Bale.ServerURL, xetURL)
		stop3 := test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))
		stop4 := test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)
		return func() { stop4(); stop3(); stop2(); stop1() }
	}

	t.Run("Access token scopes bound what it can mint", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		mint := func(token, repo, op string, status int) {
			t.Helper()
			req := NewRequest(t, "POST", "/user2/"+repo+".git/info/bale/authenticate?op="+op)
			req.SetBasicAuth("user2", token)
			MakeRequest(t, req, status)
		}
		userOnly := getUserToken(t, "user2", auth_model.AccessTokenScopeReadUser)
		mint(userOnly, "repo2", "download", http.StatusForbidden)
		mint(userOnly, "repo2", "upload", http.StatusForbidden)

		publicOnly := getUserToken(t, "user2", auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteRepository)
		mint(publicOnly, "repo2", "download", http.StatusForbidden)
		mint(publicOnly, "repo1", "download", http.StatusOK)

		readOnly := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
		mint(readOnly, "repo2", "download", http.StatusOK)
		mint(readOnly, "repo2", "upload", http.StatusForbidden)

		readWrite := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
		mint(readWrite, "repo2", "upload", http.StatusOK)
	})

	t.Run("Signed-in user without read access gets the same 404 as a missing repo", func(t *testing.T) {
		// user10/repo6 is private, owned by user10. user2 has no access.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		for _, op := range []string{"download", "upload"} {
			req := NewRequest(t, "POST", "/user10/repo6.git/info/bale/authenticate?op="+op).AddBasicAuth("user2")
			private := MakeRequest(t, req, http.StatusNotFound)
			req = NewRequest(t, "POST", "/user10/does-not-exist.git/info/bale/authenticate?op="+op).AddBasicAuth("user2")
			missing := MakeRequest(t, req, http.StatusNotFound)
			assert.Equal(t, missing.Body.String(), private.Body.String())
		}
	})

	t.Run("Upload without write access on a readable repo is 403", func(t *testing.T) {
		// user5/repo4 is public; user2 can read but not write.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		req := NewRequest(t, "POST", "/user5/repo4.git/info/bale/authenticate?op=upload").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusForbidden)
	})

	t.Run("Upload to a mirror or archived repo is 403, download still works", func(t *testing.T) {
		// org3/repo5 is a mirror user2 owns via org3; user2/repo1 is archived for
		// the duration of the subtest.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		MakeRequest(t, NewRequest(t, "POST", "/org3/repo5.git/info/bale/authenticate?op=upload").AddBasicAuth("user2"), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/org3/repo5.git/info/bale/authenticate?op=download").AddBasicAuth("user2"), http.StatusOK)

		repo1, err := repo_model.GetRepositoryByOwnerAndName(t.Context(), "user2", "repo1")
		require.NoError(t, err)
		require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), repo1, true))
		defer func() { require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), repo1, false)) }()
		MakeRequest(t, NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=upload").AddBasicAuth("user2"), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "POST", "/user2/repo1.git/info/bale/authenticate?op=download").AddBasicAuth("user2"), http.StatusOK)
	})
}
