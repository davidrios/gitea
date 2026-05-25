// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"strings"
	"testing"
	"time"

	git_model "code.gitea.io/gitea/models/git"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDFSAuthenticateHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	const xetURL = "https://cas.example.test"

	t.Run("Disabled returns 404", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, false)()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/dfs/authenticate?op=download").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusNotFound)
	})

	t.Run("Real password mints a JWT", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/dfs/authenticate?op=download").AddBasicAuth("user2")
		resp := MakeRequest(t, req, http.StatusOK)

		var got git_model.LFSTokenResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, xetURL, got.Href)
		assert.True(t, strings.HasPrefix(got.Header["Authorization"], "Bearer "))
	})

	t.Run("Missing auth returns 401 with Basic challenge", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/dfs/authenticate?op=download")
		resp := MakeRequest(t, req, http.StatusUnauthorized)
		assert.Contains(t, resp.Header().Get("WWW-Authenticate"), "Basic")
	})

	t.Run("Wrong password returns 401", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/dfs/authenticate?op=download").AddBasicAuth("user2", "nope")
		MakeRequest(t, req, http.StatusUnauthorized)
	})

	t.Run("Bad op returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()

		req := NewRequest(t, "POST", "/user2/repo1.git/info/dfs/authenticate?op=admin").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusBadRequest)
	})

	t.Run("Authenticated but write on unrelated private repo is 403", func(t *testing.T) {
		// user10/repo6 is private, owned by user10. user2 has no access.
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.DFS.Enabled, true)()
		defer test.MockVariableValue(&setting.DFS.ServerURL, xetURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("auth-http-test-secret-32-bytes!!"))()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)()

		req := NewRequest(t, "POST", "/user10/repo6.git/info/dfs/authenticate?op=upload").AddBasicAuth("user2")
		MakeRequest(t, req, http.StatusForbidden)
	})
}
