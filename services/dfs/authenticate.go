// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"encoding/base64"
	"net/http"
	"strings"

	perm_model "code.gitea.io/gitea/models/perm"
	access_model "code.gitea.io/gitea/models/perm/access"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unit"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
)

// AuthenticateHTTPHandler is the HTTPS analog of the SSH `git-dfs-authenticate`
// command. The client presents the user's gitea credentials via Basic auth,
// and the handler mints the same short-lived JWT the SSH path returns,
// scoped to that user. The credentials never leave gitea — xet-server only
// ever sees the JWT.
//
// Wire:
//
//	POST /{owner}/{repo}.git/info/dfs/authenticate?op=download|upload
//	Authorization: Basic <b64(user:password-or-PAT)>
//
//	→ 200 { "href": "<xet-server URL>",
//	        "header": { "Authorization": "Bearer <jwt>" },
//	        "expires_at": "<RFC 3339>" }
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

	username, password, ok := decodeBasic(ctx.Req.Header.Get("Authorization"))
	if !ok {
		ctx.Resp.Header().Set("WWW-Authenticate", `Basic realm="dfs"`)
		ctx.HTTPError(http.StatusUnauthorized)
		return
	}
	user, err := userFromUserPass(ctx, username, password)
	if err != nil || user == nil {
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
	perm, err := access_model.GetDoerRepoPermission(ctx, repository, user)
	if err != nil {
		log.Error("DFS authenticate: GetDoerRepoPermission(%-v, %-v): %v", repository, user, err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	if !perm.CanAccess(mode, unit.TypeCode) {
		ctx.HTTPError(http.StatusForbidden)
		return
	}

	bearer, expiresAt, err := MintEphemeralBearer(user.ID)
	if err != nil {
		log.Error("DFS authenticate: MintEphemeralBearer: %v", err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	resp := AuthenticateResponse{
		Href:      setting.DFS.ServerURL,
		Header:    map[string]string{"Authorization": "Bearer " + bearer},
		ExpiresAt: expiresAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(&resp); err != nil {
		log.Error("DFS authenticate: encode response: %v", err)
	}
}

// AuthenticateResponse is declared in token.go; both the SSH and HTTPS
// authenticate handlers emit the same shape.

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

func decodeBasic(authz string) (user, pass string, ok bool) {
	rest, found := strings.CutPrefix(authz, "Basic ")
	if !found {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest))
	if err != nil {
		return "", "", false
	}
	u, p, ok := strings.Cut(string(decoded), ":")
	if !ok || u == "" {
		return "", "", false
	}
	return u, p, true
}
