// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bale

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/bale"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/lfs"
)

// DownloadLinkTTL bounds a download link's JWT: it rides in a URL that ends up
// in browser history and proxy logs.
const DownloadLinkTTL = 5 * time.Minute

// BuildDownloadRedirectURL mints a download-link JWT and returns the
// bale-server stream URL the browser should be redirected to. The JWT rides in
// the query string because browsers can't attach an Authorization header on a
// 302 follow, so it is a lfs.BaleFileOp token: short-lived, bound to this repo
// and this one file, and refused by check_access for token exchange.
//
// A nil doer mints an anonymous (UserID 0) token: the route already gates this
// to repos the visitor can read, so anonymous browsing of a public repo's bale
// files works without a login. check_access re-verifies public read access.
//
// The token carries a SHA-256 of `filename`; bale-server must reject the
// `filename` query param unless its hash matches, so an attacker can't rewrite
// Content-Disposition on a leaked redirect URL.
func BuildDownloadRedirectURL(p bale.Pointer, repo *repo_model.Repository, doer *user_model.User, filename string) (string, error) {
	if !setting.Bale.Enabled {
		return "", errors.New("bale integration is disabled")
	}
	if setting.Bale.ServerURL == "" {
		return "", errors.New("bale server URL is not configured")
	}

	var filenameHash string
	if filename != "" {
		sum := sha256.Sum256([]byte(filename))
		filenameHash = hex.EncodeToString(sum[:])
	}

	userID := int64(0)
	if doer != nil {
		userID = doer.ID
	}

	token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
		Op: lfs.BaleFileOp, UserID: userID, RepoID: repo.ID, Bale: true,
		FilenameSHA256: filenameHash,
		FileID:         p.Hash,
		ExpiresIn:      DownloadLinkTTL,
	})
	if err != nil {
		return "", fmt.Errorf("mint bale download JWT: %w", err)
	}
	// GetLFSAuthTokenWithBearer prefixes "Bearer "; strip it for the query param.
	token = strings.TrimPrefix(token, "Bearer ")

	q := url.Values{}
	q.Set("token", token)
	q.Set("repo", CanonicalRepoID(repo))
	if filename != "" {
		q.Set("filename", filename)
	}
	return fmt.Sprintf("%s/v1/files/%s?%s", setting.Bale.ServerURL, url.PathEscape(p.Hash), q.Encode()), nil
}
