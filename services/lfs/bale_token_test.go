// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package lfs

import (
	"strings"
	"testing"
	"time"

	perm_model "code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unittest"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/services/contexttest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleBaleToken(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx, _ := contexttest.MockContext(t, "/")

	const fileA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fileB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	repo1 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}) // user2/repo1, public
	repo2 := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2}) // user2/repo2, private

	mint := func(opts AuthTokenOptions) string {
		s, err := GetLFSAuthTokenWithBearer(opts)
		require.NoError(t, err)
		_, token, _ := strings.Cut(s, " ")
		return token
	}
	fileToken := func(userID, repoID int64, fileID string) string {
		return mint(AuthTokenOptions{Bale: true, Op: BaleFileOp, UserID: userID, RepoID: repoID, FileID: fileID, ExpiresIn: 5 * time.Minute})
	}

	t.Run("token exchange accepts download and upload tokens", func(t *testing.T) {
		u, anon, err := HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 2, RepoID: 1}), repo1, perm_model.AccessModeRead, "")
		require.NoError(t, err)
		assert.False(t, anon)
		assert.EqualValues(t, 2, u.ID)

		u, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleUploadOp, UserID: 2, RepoID: 2}), repo2, perm_model.AccessModeWrite, "")
		require.NoError(t, err)
		assert.EqualValues(t, 2, u.ID)
	})

	t.Run("token exchange accepts anonymous download on a public repo only", func(t *testing.T) {
		u, anon, err := HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 0, RepoID: 1}), repo1, perm_model.AccessModeRead, "")
		require.NoError(t, err)
		assert.True(t, anon)
		assert.Nil(t, u)

		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 0, RepoID: 2}), repo2, perm_model.AccessModeRead, "")
		require.Error(t, err)

		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleUploadOp, UserID: 0, RepoID: 1}), repo1, perm_model.AccessModeRead, "")
		require.Error(t, err)
	})

	t.Run("token exchange rejects download-link tokens", func(t *testing.T) {
		_, _, err := HandleBaleToken(ctx, fileToken(2, 1, fileA), repo1, perm_model.AccessModeRead, "")
		require.Error(t, err)
		_, _, err = HandleBaleToken(ctx, fileToken(0, 1, fileA), repo1, perm_model.AccessModeRead, "")
		require.Error(t, err)
	})

	t.Run("file download accepts only a link token bound to that file", func(t *testing.T) {
		u, anon, err := HandleBaleToken(ctx, fileToken(2, 1, fileA), repo1, perm_model.AccessModeRead, fileA)
		require.NoError(t, err)
		assert.False(t, anon)
		assert.EqualValues(t, 2, u.ID)

		_, anon, err = HandleBaleToken(ctx, fileToken(0, 1, fileA), repo1, perm_model.AccessModeRead, fileA)
		require.NoError(t, err)
		assert.True(t, anon)

		_, _, err = HandleBaleToken(ctx, fileToken(2, 1, fileA), repo1, perm_model.AccessModeRead, fileB)
		require.Error(t, err, "token for file A must not unlock file B")

		_, _, err = HandleBaleToken(ctx, fileToken(2, 1, ""), repo1, perm_model.AccessModeRead, fileA)
		require.Error(t, err, "unbound link token must be rejected")

		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 2, RepoID: 1}), repo1, perm_model.AccessModeRead, fileA)
		require.Error(t, err, "token-exchange credentials are not download links")

		_, _, err = HandleBaleToken(ctx, fileToken(2, 1, fileA), repo2, perm_model.AccessModeRead, fileA)
		require.Error(t, err, "link token bound to another repo")

		_, _, err = HandleBaleToken(ctx, fileToken(0, 2, fileA), repo2, perm_model.AccessModeRead, fileA)
		require.Error(t, err, "anonymous link token on a private repo")

		_, _, err = HandleBaleToken(ctx, fileToken(2, 1, fileA), repo1, perm_model.AccessModeWrite, fileA)
		require.Error(t, err, "link tokens are read-only")
	})

	t.Run("expired download-link token is rejected", func(t *testing.T) {
		expired := mint(AuthTokenOptions{Bale: true, Op: BaleFileOp, UserID: 2, RepoID: 1, FileID: fileA, ExpiresIn: -time.Minute})
		_, _, err := HandleBaleToken(ctx, expired, repo1, perm_model.AccessModeRead, fileA)
		require.Error(t, err)
	})

	t.Run("write is rejected on mirror and archived repos", func(t *testing.T) {
		mirror := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 5})
		archived := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 51})
		require.True(t, mirror.IsMirror)
		require.True(t, archived.IsArchived)

		_, _, err := HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleUploadOp, UserID: 2, RepoID: 5}), mirror, perm_model.AccessModeWrite, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleUploadOp, UserID: 30, RepoID: 51}), archived, perm_model.AccessModeWrite, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 2, RepoID: 5}), mirror, perm_model.AccessModeRead, "")
		require.NoError(t, err)
	})

	t.Run("rejections are permission-denied errors", func(t *testing.T) {
		_, _, err := HandleBaleToken(ctx, fileToken(2, 1, fileA), repo1, perm_model.AccessModeRead, fileB)
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 2, RepoID: 1}), repo2, perm_model.AccessModeRead, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	})

	t.Run("LFS rejects download-link tokens", func(t *testing.T) {
		_, err := handleLFSToken(ctx, fileToken(2, 1, fileA), repo1, perm_model.AccessModeRead)
		require.Error(t, err)
	})

	t.Run("anonymous tokens die once sign-in is required", func(t *testing.T) {
		defer test.MockVariableValue(&setting.Service.RequireSignInViewStrict, true)()
		_, _, err := HandleBaleToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 0, RepoID: 1}), repo1, perm_model.AccessModeRead, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, _, err = HandleBaleToken(ctx, fileToken(0, 1, fileA), repo1, perm_model.AccessModeRead, fileA)
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	})

	t.Run("Bale ops without the Bale audience are rejected", func(t *testing.T) {
		// What an LFS minting path handed a "bale-upload" subverb would produce.
		_, _, err := HandleBaleToken(ctx, mint(AuthTokenOptions{Op: BaleUploadOp, UserID: 2, RepoID: 2}), repo2, perm_model.AccessModeWrite, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Op: BaleFileOp, UserID: 2, RepoID: 1, FileID: fileA}), repo1, perm_model.AccessModeRead, fileA)
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	})

	t.Run("Bale and LFS tokens are not interchangeable", func(t *testing.T) {
		_, err := handleLFSToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleDownloadOp, UserID: 2, RepoID: 1}), repo1, perm_model.AccessModeRead)
		require.Error(t, err)
		_, err = handleLFSToken(ctx, mint(AuthTokenOptions{Bale: true, Op: BaleUploadOp, UserID: 2, RepoID: 2}), repo2, perm_model.AccessModeWrite)
		require.Error(t, err)
		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Op: "download", UserID: 2, RepoID: 1}), repo1, perm_model.AccessModeRead, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
		_, _, err = HandleBaleToken(ctx, mint(AuthTokenOptions{Op: "upload", UserID: 2, RepoID: 2}), repo2, perm_model.AccessModeWrite, "")
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	})
}
