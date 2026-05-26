// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

// Package bale implements gitea's server-side surface for the git-bale
// integration. It does NOT host object bytes — those live on a separate
// baleforgit-server.
package bale

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

type DiscoveryResponse struct {
	ServerURL string `json:"server_url"`
}

// DiscoveryHandler serves GET /{owner}/{repo}.git/info/bale. Returns 404 on
// Bale-disabled, missing repo, or no read access — matching gitea's other repo
// endpoints so anonymous probes can't tell private repos exist.
func DiscoveryHandler(ctx *context.Context) {
	if !setting.Bale.Enabled {
		ctx.HTTPError(http.StatusNotFound)
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
		log.Error("Bale discovery: GetDoerRepoPermission(%-v, %-v): %v", repository, ctx.Doer, err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	if !perm.CanRead(unit.TypeCode) {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(DiscoveryResponse{ServerURL: setting.Bale.ServerURL}); err != nil {
		log.Error("Bale discovery: encode response: %v", err)
	}
}
