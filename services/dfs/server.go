// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package dfs implements gitea's server-side surface for the git-dfs
// integration. Unlike the LFS service, this package does NOT host object
// bytes — those live on a separate xet-server. Today the only handler here
// is the URL-discovery endpoint; auth + transfer-token endpoints arrive in
// later milestones (M-gitea-3, M-gitea-4).
package dfs

import (
	"net/http"
	"strings"

	access_model "code.gitea.io/gitea/models/perm/access"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unit"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
)

// DiscoveryResponse is what `GET /{owner}/{repo}.git/info/dfs` returns when
// DFS is enabled. Clients (git-dfs) read `server_url` and use it as their
// `dfs.serverUrl`, then go directly to xet-server for CAS calls.
type DiscoveryResponse struct {
	// ServerURL is the public base URL of the xet-server, no trailing slash.
	ServerURL string `json:"server_url"`
}

// DiscoveryHandler serves the URL-discovery endpoint. Behavior:
//   - 404 if DFS is globally disabled (the route mount also guards this, but
//     keeping the check here makes the handler safe to call directly in tests).
//   - 404 if the repo doesn't exist OR the caller lacks read access on its
//     code unit — same shape as gitea's other repo endpoints, doesn't leak
//     existence of private repos to anonymous probes.
//   - 200 with `{"server_url": "..."}` otherwise.
func DiscoveryHandler(ctx *context.Context) {
	if !setting.DFS.Enabled {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	ownerName := ctx.PathParam("username")
	repoName := strings.TrimSuffix(ctx.PathParam("reponame"), ".git")

	repository, err := repo_model.GetRepositoryByOwnerAndName(ctx, ownerName, repoName)
	if err != nil {
		// includes ErrRepoNotExist — treat both as 404 to avoid existence leaks.
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	perm, err := access_model.GetDoerRepoPermission(ctx, repository, ctx.Doer)
	if err != nil {
		log.Error("DFS discovery: GetDoerRepoPermission(%-v, %-v): %v", repository, ctx.Doer, err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	if !perm.CanRead(unit.TypeCode) {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(DiscoveryResponse{ServerURL: setting.DFS.ServerURL}); err != nil {
		log.Error("DFS discovery: encode response: %v", err)
	}
}
