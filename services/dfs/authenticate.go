// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

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

// AuthenticateHTTPHandler is the HTTPS analog of the SSH `git-dfs-authenticate`
// command. ctx.Doer is populated by gitea's `webAuth.AllowBasic` middleware
// from the request's `Authorization: Basic` header (password or PAT), so this
// handler doesn't need to touch credentials — by the time we run, the user
// is either authenticated or anonymous.
//
// Wire:
//
//	POST /{owner}/{repo}.git/info/dfs/authenticate?op=download|upload
//	Authorization: Basic <b64(user:password-or-PAT)>
//
//	→ 200 git_model.LFSTokenResponse { href, header.Authorization=Bearer <jwt> }
//	→ 401  bad / missing credentials
//	→ 403  authenticated, but user lacks the requested scope on the repo
//	→ 400  unknown op
//	→ 404  DFS disabled, or repo invisible
func AuthenticateHTTPHandler(ctx *context.Context) {
	if !setting.DFS.Enabled {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	op := ctx.FormString("op")
	mode, ok := opToAccessMode(op)
	if !ok {
		ctx.HTTPError(http.StatusBadRequest, "op must be 'download' or 'upload'")
		return
	}

	if ctx.Doer == nil {
		ctx.Resp.Header().Set("WWW-Authenticate", `Basic realm="dfs"`)
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
	perm, err := access_model.GetDoerRepoPermission(ctx, repository, ctx.Doer)
	if err != nil {
		log.Error("DFS authenticate: GetDoerRepoPermission(%-v, %-v): %v", repository, ctx.Doer, err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	if !perm.CanAccess(mode, unit.TypeCode) {
		ctx.HTTPError(http.StatusForbidden)
		return
	}

	// Reuse LFS's JWT minter — same HS256 secret, same expiry, same claim
	// shape (UserID + RepoID + Op). The JWT is repo-scoped: check_access
	// will refuse to honor it against any other repo.
	token, err := lfs.GetLFSAuthTokenWithBearer(lfs.AuthTokenOptions{
		Op: op, UserID: ctx.Doer.ID, RepoID: repository.ID,
	})
	if err != nil {
		log.Error("DFS authenticate: mint JWT: %v", err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}

	resp := git_model.LFSTokenResponse{
		Href:   setting.DFS.ServerURL,
		Header: map[string]string{"Authorization": token},
	}
	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(&resp); err != nil {
		log.Error("DFS authenticate: encode response: %v", err)
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
