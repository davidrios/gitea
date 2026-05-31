// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/lfs"
	"code.gitea.io/gitea/tests"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBaleWebDownload checks that the web /media/ endpoint serves a public
// repo's Bale file to an anonymous visitor: it 303s to the bale-server with an
// anonymous (UserID 0) download token, so "view raw" / inline preview works
// without a login.
func TestBaleWebDownload(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		const serverURL = "https://cas.example.test"
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, serverURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte("web-download-test-secret-32-byte"))()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 5*time.Minute)()

		// Commit a valid Bale pointer file into the public repo user2/repo1.
		hash := strings.Repeat("a", 64)
		pointer := fmt.Sprintf(`{"hash":"%s","file_size":2048,"sha256":"%s"}`, hash, strings.Repeat("b", 64))
		const treePath = "bale/model.bin"

		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
		createOpts := getCreateFileOptions()
		createOpts.ContentBase64 = base64.StdEncoding.EncodeToString([]byte(pointer))
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/"+treePath, &createOpts).AddTokenAuth(token)
		MakeRequest(t, req, http.StatusCreated)

		t.Run("Anonymous media request on a public repo redirects with an anonymous token", func(t *testing.T) {
			defer tests.PrintCurrentTest(t)()

			req := NewRequest(t, "GET", "/user2/repo1/media/branch/master/"+treePath)
			resp := MakeRequest(t, req, http.StatusSeeOther)

			loc, err := url.Parse(resp.Header().Get("Location"))
			require.NoError(t, err)
			assert.Equal(t, serverURL, loc.Scheme+"://"+loc.Host)
			assert.Equal(t, "/v1/files/"+hash, loc.Path)
			assert.Equal(t, "user2/repo1", loc.Query().Get("repo"))
			assert.Equal(t, "model.bin", loc.Query().Get("filename"))

			claims := &lfs.Claims{}
			parsed, err := jwt.ParseWithClaims(loc.Query().Get("token"), claims, func(*jwt.Token) (any, error) {
				return setting.LFS.JWTSecretBytes, nil
			})
			require.NoError(t, err)
			require.True(t, parsed.Valid)
			assert.Equal(t, int64(0), claims.UserID, "anonymous principal carries UserID 0")
			assert.Equal(t, "download", claims.Op)

			// The token binds the filename so bale-server can reject a rewritten name.
			want := sha256.Sum256([]byte("model.bin"))
			assert.Equal(t, hex.EncodeToString(want[:]), claims.FilenameSHA256)
		})
	})
}
