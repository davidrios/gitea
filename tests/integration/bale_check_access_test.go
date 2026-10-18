// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
		tokenOp, ok := lfs.BaleTokenOp(op)
		require.True(t, ok)
		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Op: tokenOp, UserID: userID, RepoID: repoID, Bale: true,
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

	bodyWith := func(hubBearer, repoID, scope, purpose, fileID string) string {
		req := bale.CheckAccessRequest{
			HubBearer: hubBearer,
			Repo: bale.CheckAccessRepoRef{
				RepoType: "model",
				RepoID:   repoID,
				Revision: "main",
			},
			Scope:   scope,
			Purpose: purpose,
			FileID:  fileID,
		}
		b, err := json.Marshal(req)
		require.NoError(t, err)
		return string(b)
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
	canonical1 := fmt.Sprintf("id/%d", repo1.ID)
	canonical2 := fmt.Sprintf("id/%d", repo2.ID)
	owner1 := strconv.FormatInt(repo1.OwnerID, 10)
	owner2 := strconv.FormatInt(repo2.OwnerID, 10)

	const fileA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const fileB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	mintFile := func(t *testing.T, userID, repoID int64, fileID string) string {
		t.Helper()
		defer withBale()()
		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Bale: true, Op: lfs.BaleFileOp, UserID: userID, RepoID: repoID, FileID: fileID, ExpiresIn: bale.DownloadLinkTTL,
		})
		require.NoError(t, err)
		return token
	}
	decodeOK := func(t *testing.T, resp *httptest.ResponseRecorder) bale.CheckAccessResponse {
		t.Helper()
		require.Equal(t, http.StatusOK, resp.Code)
		var got bale.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		return got
	}

	t.Run("Case variants of the typed name resolve to the same canonical repo_id", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		got := decodeOK(t, post(t, body(user2ReadRepo1, "User2/Repo1", "read")))
		assert.Equal(t, canonical1, got.RepoID)
		assert.Equal(t, owner1, got.Owner)
	})

	t.Run("Canonical numeric repo_id is accepted as input", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		got := decodeOK(t, post(t, body(user2ReadRepo1, canonical1, "read")))
		assert.Equal(t, "user2", got.UserID)
		assert.Equal(t, canonical1, got.RepoID)
		assert.Equal(t, owner1, got.Owner)
	})

	t.Run("Valid token for one repo presented with another repo's canonical id is 401", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2WriteRepo2, canonical1, "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Typed names are not checked: the token's repo is the scope", func(t *testing.T) {
		// A clone may still use a pre-rename/transfer name; the scope comes from
		// the token's RepoID either way.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		for _, typed := range []string{"olduser/oldname", "user2/repo2", fmt.Sprintf("%d/%d", repo1.OwnerID, repo1.ID)} {
			got := decodeOK(t, post(t, body(user2ReadRepo1, typed, "read")))
			assert.Equal(t, canonical1, got.RepoID, typed)
			assert.Equal(t, owner1, got.Owner, typed)
		}
	})

	t.Run("Write is rejected on mirror and archived repos", func(t *testing.T) {
		// org3/repo5 is a mirror user2 owns via org3; user2/repo2 is archived for
		// the duration of the subtest.
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		assert.Equal(t, http.StatusUnauthorized, post(t, body(mintFor(t, 2, 5, "upload"), "org3/repo5", "write")).Code)
		assert.Equal(t, "id/5", decodeOK(t, post(t, body(mintFor(t, 2, 5, "download"), "org3/repo5", "read"))).RepoID)

		archived, err := repo_model.GetRepositoryByID(t.Context(), repo2.ID)
		require.NoError(t, err)
		require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), archived, true))
		defer func() { require.NoError(t, repo_model.SetArchiveRepoState(t.Context(), archived, false)) }()
		assert.Equal(t, http.StatusUnauthorized, post(t, body(user2WriteRepo2, "user2/repo2", "write")).Code)
		assert.Equal(t, canonical2, decodeOK(t, post(t, body(mintFor(t, 2, repo2.ID, "download"), "user2/repo2", "read"))).RepoID)
	})

	t.Run("Oversized body is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		big := bodyWith(user2ReadRepo1, "user2/repo1", "read", "", strings.Repeat("a", 65<<10))
		assert.Equal(t, http.StatusBadRequest, post(t, big).Code)
	})

	t.Run("Expired download-link token is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Bale: true, Op: lfs.BaleFileOp, UserID: 2, RepoID: repo1.ID, FileID: fileA, ExpiresIn: -time.Minute,
		})
		require.NoError(t, err)
		resp := post(t, bodyWith(token, canonical1, "read", bale.PurposeFileDownload, fileA))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Anonymous probes of missing and private repos look like a bad token", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		badToken := post(t, body("not-a-jwt", "user2/repo1", "read"))
		require.Equal(t, http.StatusUnauthorized, badToken.Code)

		anonRepo1 := mintFor(t, 0, repo1.ID, "download")
		anonRepo2 := mintFor(t, 0, repo2.ID, "download")
		for _, resp := range []*httptest.ResponseRecorder{
			post(t, body(anonRepo1, "id/999999", "read")),
			post(t, body(anonRepo2, "user2/repo2", "read")),
			post(t, body(anonRepo2, canonical2, "read")),
			post(t, body(mintFor(t, 0, 999999, "download"), "id/999999", "read")),
		} {
			assert.Equal(t, badToken.Code, resp.Code)
			assert.Equal(t, badToken.Body.String(), resp.Body.String())
		}
	})

	t.Run("Download-link token is accepted for its own file", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		got := decodeOK(t, post(t, bodyWith(mintFile(t, 2, repo1.ID, fileA), canonical1, "read", bale.PurposeFileDownload, fileA)))
		assert.Equal(t, "user2", got.UserID)
		assert.Equal(t, canonical1, got.RepoID)
		assert.Equal(t, owner1, got.Owner)

		got = decodeOK(t, post(t, bodyWith(mintFile(t, 0, repo1.ID, fileA), canonical1, "read", bale.PurposeFileDownload, fileA)))
		assert.Equal(t, bale.AnonymousUserID, got.UserID)
	})

	t.Run("Download-link token is rejected for another file", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, bodyWith(mintFile(t, 2, repo1.ID, fileA), canonical1, "read", bale.PurposeFileDownload, fileB))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Download-link token is rejected for token exchange", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		link := mintFile(t, 2, repo1.ID, fileA)
		assert.Equal(t, http.StatusUnauthorized, post(t, bodyWith(link, "user2/repo1", "read", bale.PurposeToken, "")).Code)
		assert.Equal(t, http.StatusUnauthorized, post(t, body(link, "user2/repo1", "read")).Code, "absent purpose means token exchange")
	})

	t.Run("Token-exchange JWT is rejected for file download", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, bodyWith(user2ReadRepo1, canonical1, "read", bale.PurposeFileDownload, fileA))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("File download without file_id or with unknown purpose returns 400", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		assert.Equal(t, http.StatusBadRequest, post(t, bodyWith(user2ReadRepo1, canonical1, "read", bale.PurposeFileDownload, "")).Code)
		assert.Equal(t, http.StatusBadRequest, post(t, bodyWith(user2ReadRepo1, canonical1, "read", "admin", "")).Code)
	})

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
		assert.Equal(t, canonical1, got.RepoID)
		assert.Equal(t, owner1, got.Owner)
	})

	t.Run("Write JWT on the private repo it was minted for returns username", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(user2WriteRepo2, "user2/repo2", "write"))
		require.Equal(t, http.StatusOK, resp.Code)
		var got bale.CheckAccessResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&got))
		assert.Equal(t, "user2", got.UserID)
		assert.Equal(t, canonical2, got.RepoID)
		assert.Equal(t, owner2, got.Owner)
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
		assert.Equal(t, canonical1, got.RepoID)
		assert.Equal(t, owner1, got.Owner)
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

		resp := post(t, body(user2ReadRepo1, canonical2, "read"))
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

	t.Run("Token bound to a nonexistent repo returns 401", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer withBale()()

		resp := post(t, body(mintFor(t, 2, 999999, "download"), "user2/does-not-exist", "read"))
		assert.Equal(t, http.StatusUnauthorized, resp.Code)
	})

	t.Run("Expired JWT is rejected", func(t *testing.T) {
		defer tests.PrintCurrentTest(t)()
		defer test.MockVariableValue(&setting.Bale.Enabled, true)()
		defer test.MockVariableValue(&setting.Bale.ServerURL, expectedURL)()
		defer test.MockVariableValue(&setting.LFS.JWTSecretBytes, jwtSecret)()
		defer test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, -time.Minute)()

		token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
			Bale: true, Op: lfs.BaleDownloadOp, UserID: 2, RepoID: repo1.ID,
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
			Bale: true, Op: lfs.BaleDownloadOp, UserID: 2, RepoID: repo1.ID,
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
