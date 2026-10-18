// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bale

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/bale"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/services/lfs"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildDownloadRedirectURL(t *testing.T) {
	const hash = "0000000000000000000000000000000000000000000000000000000000000001"
	const server = "https://cas.example.test"
	const secret = "download-test-secret-32-bytes!!!"

	defer test.MockVariableValue(&setting.Bale.Enabled, true)()
	defer test.MockVariableValue(&setting.Bale.ServerURL, server)()
	defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, []byte(secret))()
	// The LFS default (24h) must not leak into download links.
	defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, 24*time.Hour)()

	doer := &user_model.User{ID: 42}
	repo := &repo_model.Repository{ID: 99, OwnerID: 7, OwnerName: "alice", Name: "models"}
	ptr := bale.Pointer{Hash: hash, FileSize: 1234}

	t.Run("Builds a redirect URL with token and filename", func(t *testing.T) {
		raw, err := BuildDownloadRedirectURL(ptr, repo, doer, "big file.bin")
		require.NoError(t, err)

		assert.True(t, strings.HasPrefix(raw, server+"/v1/files/"+hash+"?"), "got %s", raw)
		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Equal(t, "big file.bin", u.Query().Get("filename"))
		assert.Equal(t, "id/99", u.Query().Get("repo"), "repo must be the rename/transfer-stable id/<repoID>")

		token := u.Query().Get("token")
		require.NotEmpty(t, token)
		assert.False(t, strings.HasPrefix(token, "Bearer "), "token should not carry the Bearer prefix in the URL")

		claims := &lfs.Claims{}
		parsed, err := jwt.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
			return setting.LFS.JWTSecretBytes, nil
		})
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		assert.Equal(t, repo.ID, claims.RepoID)
		assert.Equal(t, doer.ID, claims.UserID)
		assert.Equal(t, lfs.BaleFileOp, claims.Op, "link tokens must not be token-exchange credentials")
		assert.Equal(t, hash, claims.FileID)
		require.NotNil(t, claims.ExpiresAt)
		assert.LessOrEqual(t, time.Until(claims.ExpiresAt.Time), DownloadLinkTTL)
		assert.Greater(t, time.Until(claims.ExpiresAt.Time), DownloadLinkTTL-time.Minute)

		// Filename binding: SHA-256 of the filename must be present in the claim
		// so baleforgit-server can refuse a rewritten `filename` query param.
		want := sha256.Sum256([]byte("big file.bin"))
		assert.Equal(t, hex.EncodeToString(want[:]), claims.FilenameSHA256)
	})

	t.Run("Empty filename omits both the query param and the hash claim", func(t *testing.T) {
		raw, err := BuildDownloadRedirectURL(ptr, repo, doer, "")
		require.NoError(t, err)

		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Empty(t, u.Query().Get("filename"))

		claims := &lfs.Claims{}
		_, err = jwt.ParseWithClaims(u.Query().Get("token"), claims, func(*jwt.Token) (any, error) {
			return setting.LFS.JWTSecretBytes, nil
		})
		require.NoError(t, err)
		assert.Empty(t, claims.FilenameSHA256)
	})

	t.Run("Disabled returns an error", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Bale.Enabled, false)()
		_, err := BuildDownloadRedirectURL(ptr, repo, doer, "x.bin")
		require.Error(t, err)
	})

	t.Run("Missing server URL returns an error", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Bale.ServerURL, "")()
		_, err := BuildDownloadRedirectURL(ptr, repo, doer, "x.bin")
		require.Error(t, err)
	})

	t.Run("Anonymous doer mints a UserID 0 token", func(t *testing.T) {
		raw, err := BuildDownloadRedirectURL(ptr, repo, nil, "x.bin")
		require.NoError(t, err)

		u, err := url.Parse(raw)
		require.NoError(t, err)

		claims := &lfs.Claims{}
		parsed, err := jwt.ParseWithClaims(u.Query().Get("token"), claims, func(*jwt.Token) (any, error) {
			return setting.LFS.JWTSecretBytes, nil
		})
		require.NoError(t, err)
		require.True(t, parsed.Valid)
		assert.Equal(t, int64(0), claims.UserID)
		assert.Equal(t, lfs.BaleFileOp, claims.Op)
		assert.Equal(t, hash, claims.FileID)
	})
}

func TestCanonicalRepoID(t *testing.T) {
	repo := &repo_model.Repository{ID: 99, OwnerID: 7, OwnerName: "Alice", Name: "Models"}
	assert.Equal(t, "id/99", CanonicalRepoID(repo))
	assert.Equal(t, "7", CanonicalOwnerID(repo.OwnerID))

	for in, want := range map[string]bool{
		"id/99":        false,
		"id/98":        true,
		"id/0":         true,
		"Alice/Models": false,
		"olduser/old":  false,
		"7/99":         false,
		"id/abc":       false,
	} {
		assert.Equal(t, want, repoRefConflicts(in, repo), in)
	}

	// An owner literally named "id" with a numeric repo name is a name, not an id.
	named := &repo_model.Repository{ID: 42, OwnerName: "id", Name: "5"}
	assert.False(t, repoRefConflicts("id/5", named))
	assert.True(t, repoRefConflicts("id/6", named))
}

func TestIsAccessRejection(t *testing.T) {
	assert.True(t, isAccessRejection(util.NewPermissionDeniedErrorf("x")))
	assert.True(t, isAccessRejection(repo_model.ErrRepoNotExist{ID: 1}))
	assert.True(t, isAccessRejection(user_model.ErrUserNotExist{UID: 1}))
	assert.False(t, isAccessRejection(errors.New("database is locked")))
}
