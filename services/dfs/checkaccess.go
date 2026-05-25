// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"errors"
	"net/http"
	"strings"

	auth_model "code.gitea.io/gitea/models/auth"
	perm_model "code.gitea.io/gitea/models/perm"
	access_model "code.gitea.io/gitea/models/perm/access"
	repo_model "code.gitea.io/gitea/models/repo"
	"code.gitea.io/gitea/models/unit"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/services/context"
)

// Wire shape mirrors the contract in `crates/xet-server-authz-http/src/lib.rs`:
//
//	POST /-/dfs/check_access
//	Content-Type: application/json
//	{ "hub_bearer": "...", "repo": { "repo_type": "...", "repo_id": "owner/name",
//	                                 "revision": "..." }, "scope": "read"|"write" }
//
// The `hub_bearer` field is the only credential — callers prove they're
// acting for the user by holding either that user's PAT or a gitea-issued
// ephemeral JWT. There's no separate "I am xet-server" credential because
// the endpoint doesn't expose anything beyond what holding a valid bearer
// already grants via gitea's normal API.
//
// Responses:
//
//	200 { "user_id": "<gitea-username>" }
//	401 — unknown hub_bearer
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

// CheckAccessHandler is the upstream-authz hook called by xet-server's
// `HttpAuthz::check_repo_access`. Authentication of the request itself is
// implicit: the `hub_bearer` field must be a valid PAT or ephemeral JWT
// that gitea recognizes for the named repo.
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

	user, err := userFromHubBearer(ctx, req.HubBearer)
	if err != nil || user == nil {
		ctx.HTTPError(http.StatusUnauthorized)
		return
	}

	owner, name, ok := strings.Cut(req.Repo.RepoID, "/")
	if !ok || owner == "" || name == "" {
		ctx.HTTPError(http.StatusBadRequest, "repo_id must be 'owner/name'")
		return
	}

	repository, err := repo_model.GetRepositoryByOwnerAndName(ctx, owner, name)
	if err != nil {
		// 403 (known user, missing access) rather than 404 — the user
		// authenticated, just lacks visibility. Treating "unknown repo" as
		// 403 here matches what xet-server already gets when access is
		// denied to a real repo, so the client sees a consistent shape.
		ctx.HTTPError(http.StatusForbidden)
		return
	}

	perm, err := access_model.GetDoerRepoPermission(ctx, repository, user)
	if err != nil {
		log.Error("DFS check_access: GetUserRepoPermission(%-v, %-v): %v", repository, user, err)
		ctx.HTTPError(http.StatusInternalServerError)
		return
	}
	if !perm.CanAccess(requestedMode, unit.TypeCode) {
		ctx.HTTPError(http.StatusForbidden)
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

// userFromHubBearer resolves a hub_bearer string to a gitea user. Two shapes
// are accepted:
//
//   - PAT: 40-char lowercase hex SHA1 — the HTTPS git-credential path.
//   - Ephemeral DFS JWT (issuer `gitea-dfs`) — the SSH `git-dfs-authenticate`
//     path. JWTs are distinguishable by containing a `.` character, which
//     never appears in a PAT.
//
// Anything else is rejected.
func userFromHubBearer(ctx *context.Context, bearer string) (*user_model.User, error) {
	bearer = strings.TrimSpace(bearer)
	if bearer == "" {
		return nil, errors.New("empty bearer")
	}
	if strings.Contains(bearer, ".") {
		userID, err := ParseEphemeralBearer(bearer)
		if err != nil {
			return nil, err
		}
		return user_model.GetUserByID(ctx, userID)
	}
	token, err := auth_model.GetAccessTokenBySHA(ctx, bearer)
	if err != nil {
		return nil, err
	}
	return user_model.GetUserByID(ctx, token.UID)
}
