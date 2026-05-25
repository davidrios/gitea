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

// Wire shape mirrors the contract in `crates/xet-server-authz-http/src/lib.rs`:
//
//	POST /-/dfs/check_access
//	Content-Type: application/json
//	{ "hub_bearer": "...", "repo": { "repo_type": "...", "repo_id": "owner/name",
//	                                 "revision": "..." }, "scope": "read"|"write" }
//
// `hub_bearer` is the JWT minted by the `/info/dfs/authenticate` or
// SSH `git-dfs-authenticate` paths. Verification is delegated to
// `lfs.HandleLFSToken`, which parses the JWT, asserts it binds to `repo`,
// and re-checks the user's current scope on the code unit.
//
// Responses:
//
//	200 { "user_id": "<gitea-username>" }
//	401 — unknown / invalid hub_bearer
//	403 — known user lacks the requested scope on the repo
//	400 — malformed body / unparseable repo_id
type CheckAccessRequest struct {
	HubBearer string             `json:"hub_bearer"`
	Repo      CheckAccessRepoRef `json:"repo"`
	Scope     string             `json:"scope"`
}

// CheckAccessRepoRef matches xet-server-core's `RepoRef`. `RepoType` and
// `Revision` aren't load-bearing on the gitea side today — every gitea repo
// is a single "code" unit and DFS access doesn't depend on branch — but we
// accept the fields verbatim so the contract round-trips cleanly.
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
		// 403 (known user, missing access) rather than 404 — matches what
		// xet-server already gets when access is denied to a real repo, so
		// the client sees a consistent shape.
		ctx.HTTPError(http.StatusForbidden)
		return
	}

	// HandleLFSToken does it all: parse JWT, verify signature/exp/nbf, check
	// the JWT's RepoID matches `repository`, check the JWT's Op covers
	// `requestedMode`, look up the user, and re-check their permission. A
	// failure could be 401 (bad JWT) or 403 (scope mismatch); we can't
	// distinguish without parsing the error message, so map both to 401 —
	// caller has nothing actionable to do with the difference.
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
