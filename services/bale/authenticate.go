// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bale

import (
	"net/http"
	"strings"

	git_model "code.gitea.io/gitea/models/git"
	perm_model "code.gitea.io/gitea/models/perm"
	access_model "code.gitea.io/gitea/models/perm/access"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unit"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/lfs"
)

// AuthenticateHTTPHandler is the HTTPS analog of `git-bale-authenticate`.
// ctx.Doer is populated by webAuth.AllowBasic from the request's Basic auth
// header, so credentials never reach this handler directly. A nil ctx.Doer here
// means no credentials were presented (wrong credentials are already rejected
// upstream with 401): an anonymous request, allowed only as a public download.
//
//	POST /{owner}/{repo}.git/info/bale/authenticate?op=download|upload
//	→ 200 LFSTokenResponse, 401 missing creds (private repo or any upload),
//	  403 wrong scope, 400 unknown op, 404 Bale disabled or repo invisible
func AuthenticateHTTPHandler(ctx *context.Context) {
	if !setting.Bale.Enabled {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	op := ctx.FormString("op")
	mode, ok := opToAccessMode(op)
	if !ok {
		ctx.HTTPError(http.StatusBadRequest, "op must be 'download' or 'upload'")
		return
	}

	// Anonymous writes are never granted — only a download can be credential-less.
	if mode == perm_model.AccessModeWrite && ctx.Doer == nil {
		ctx.Resp.Header().Set("WWW-Authenticate", `Basic realm="bale"`)
		ctx.HTTPError(http.StatusUnauthorized)
		return
	}

	ownerName := ctx.PathParam("username")
	repoName := strings.TrimSuffix(ctx.PathParam("reponame"), ".git")
	repository, err := repo_model.GetRepositoryByOwnerAndName(ctx, ownerName, repoName)
	if err != nil {
		ctx.HTTPError(http.StatusNotFound)
		return
	}
	// ctx.Doer may be nil (anonymous): GetDoerRepoPermission resolves read access
	// for an anonymous visitor on a public repo and denies it on a private one.
	perm, err := access_model.GetDoerRepoPermission(ctx, repository, ctx.Doer)
	if err != nil {
		log.Error("Bale authenticate: GetDoerRepoPermission(%-v, %-v): %v", repository, ctx.Doer, err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	if !perm.CanAccess(mode, unit.TypeCode) {
		// Anonymous request that can't read (private repo) → challenge for
		// credentials with 401; an authenticated user lacking scope → 403.
		if ctx.Doer == nil {
			ctx.Resp.Header().Set("WWW-Authenticate", `Basic realm="bale"`)
			ctx.HTTPError(http.StatusUnauthorized)
			return
		}
		ctx.HTTPError(http.StatusForbidden)
		return
	}

	// Anonymous reads carry UserID 0; check_access resolves that to the anonymous
	// principal and re-verifies public read access.
	userID := int64(0)
	if ctx.Doer != nil {
		userID = ctx.Doer.ID
	}

	// Reuse LFS's JWT minter — same secret, same claim shape. check_access
	// refuses to honor the JWT against any other repo.
	token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
		Op: op, UserID: userID, RepoID: repository.ID,
	})
	if err != nil {
		log.Error("Bale authenticate: mint JWT: %v", err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}

	resp := git_model.LFSTokenResponse{
		Href:   setting.Bale.ServerURL,
		Header: map[string]string{"Authorization": token},
	}
	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(&resp); err != nil {
		log.Error("Bale authenticate: encode response: %v", err)
	}
}

func opToAccessMode(op string) (perm_model.AccessMode, bool) {
	switch op {
	case "download":
		return perm_model.AccessModeRead, true
	case "upload":
		return perm_model.AccessModeWrite, true
	default:
		return 0, false
	}
}
