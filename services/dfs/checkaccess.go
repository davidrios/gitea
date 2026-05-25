// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"net/http"
	"strings"

	perm_model "code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/lfs"
)

// Wire shape mirrors crates/xet-server-authz-http/src/lib.rs:
//
//	POST /-/dfs/check_access
//	{ "hub_bearer": "...", "repo": { "repo_type": "...", "repo_id": "owner/name",
//	                                 "revision": "..." }, "scope": "read"|"write" }
type CheckAccessRequest struct {
	HubBearer string             `json:"hub_bearer"`
	Repo      CheckAccessRepoRef `json:"repo"`
	Scope     string             `json:"scope"`
}

// CheckAccessRepoRef matches xet-server-core's RepoRef. RepoType/Revision
// aren't load-bearing on the gitea side but the contract round-trips them.
type CheckAccessRepoRef struct {
	RepoType string `json:"repo_type"`
	RepoID   string `json:"repo_id"`
	Revision string `json:"revision"`
}

type CheckAccessResponse struct {
	UserID string `json:"user_id"`
}

func CheckAccessHandler(ctx *context.Context) {
	if !setting.DFS.Enabled {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	var req CheckAccessRequest
	if err := json.NewDecoder(ctx.Req.Body).Decode(&req); err != nil {
		ctx.HTTPError(http.StatusBadRequest, "invalid JSON body")
		return
	}

	requestedMode, ok := scopeToAccessMode(req.Scope)
	if !ok {
		ctx.HTTPError(http.StatusBadRequest, "scope must be 'read' or 'write'")
		return
	}

	owner, name, ok := strings.Cut(req.Repo.RepoID, "/")
	if !ok || owner == "" || name == "" {
		ctx.HTTPError(http.StatusBadRequest, "repo_id must be 'owner/name'")
		return
	}

	repository, err := repo_model.GetRepositoryByOwnerAndName(ctx, owner, name)
	if err != nil {
		// 403 instead of 404 to match what xet-server returns on denied access.
		ctx.HTTPError(http.StatusForbidden)
		return
	}

	// HandleLFSToken parses+verifies the JWT, asserts it binds to `repository`,
	// and re-checks scope. Bad JWT and scope mismatch both return non-nil err;
	// we map both to 401 since the caller has nothing actionable to do with
	// the difference.
	bearer := strings.TrimPrefix(strings.TrimSpace(req.HubBearer), "Bearer ")
	user, err := lfs.HandleLFSToken(ctx, bearer, repository, requestedMode)
	if err != nil || user == nil {
		log.Trace("DFS check_access: bearer rejected for %s/%s: %v", owner, name, err)
		ctx.HTTPError(http.StatusUnauthorized)
		return
	}

	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(CheckAccessResponse{UserID: user.Name}); err != nil {
		log.Error("DFS check_access: encode response: %v", err)
	}
}

func scopeToAccessMode(s string) (perm_model.AccessMode, bool) {
	switch s {
	case "read":
		return perm_model.AccessModeRead, true
	case "write":
		return perm_model.AccessModeWrite, true
	default:
		return 0, false
	}
}
