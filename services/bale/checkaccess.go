// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bale

import (
	"errors"
	"net/http"
	"strings"

	perm_model "code.gitea.io/gitea/models/perm"
	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/util"
	"code.gitea.io/gitea/services/context"
	"code.gitea.io/gitea/services/lfs"
)

// AnonymousUserID is the subject baleforgit-server gets back for a credential-less
// public read (the anonymous principal minted by the authenticate endpoint).
const AnonymousUserID = "anonymous"

// Purposes baleforgit-server sends; an absent purpose means token exchange.
const (
	PurposeToken        = "token"
	PurposeFileDownload = "file-download"
)

// Wire shape mirrors crates/bale-server-authz-http/src/lib.rs:
//
//	POST /-/bale/check_access
//	{ "hub_bearer": "...", "repo": { "repo_type": "...", "repo_id": "owner/name",
//	                                 "revision": "..." }, "scope": "read"|"write",
//	  "purpose": "token"|"file-download", "file_id": "<hex>" (downloads only) }
type CheckAccessRequest struct {
	HubBearer string             `json:"hub_bearer"`
	Repo      CheckAccessRepoRef `json:"repo"`
	Scope     string             `json:"scope"`
	Purpose   string             `json:"purpose,omitempty"`
	FileID    string             `json:"file_id,omitempty"`
}

// CheckAccessRepoRef matches baleforgit-server-core's RepoRef. RepoType/Revision
// aren't load-bearing on the gitea side but the contract round-trips them.
type CheckAccessRepoRef struct {
	RepoType string `json:"repo_type"`
	RepoID   string `json:"repo_id"`
	Revision string `json:"revision"`
}

// CheckAccessResponse carries the canonical scope key and quota owner (see identity.go).
type CheckAccessResponse struct {
	UserID string `json:"user_id"`
	RepoID string `json:"repo_id"`
	Owner  string `json:"owner"`
}

const maxCheckAccessBodyBytes = 64 << 10

func CheckAccessHandler(ctx *context.Context) {
	if !setting.Bale.Enabled {
		ctx.HTTPError(http.StatusNotFound)
		return
	}

	var req CheckAccessRequest
	body := http.MaxBytesReader(ctx.Resp, ctx.Req.Body, maxCheckAccessBodyBytes)
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		ctx.HTTPError(http.StatusBadRequest, "invalid JSON body")
		return
	}

	requestedMode, ok := scopeToAccessMode(req.Scope)
	if !ok {
		ctx.HTTPError(http.StatusBadRequest, "scope must be 'read' or 'write'")
		return
	}

	var fileID string
	switch req.Purpose {
	case "", PurposeToken:
	case PurposeFileDownload:
		if req.FileID == "" {
			ctx.HTTPError(http.StatusBadRequest, "file_id is required for file-download")
			return
		}
		fileID = req.FileID
	default:
		ctx.HTTPError(http.StatusBadRequest, "purpose must be 'token' or 'file-download'")
		return
	}

	owner, name, ok := strings.Cut(req.Repo.RepoID, "/")
	if !ok || owner == "" || name == "" {
		ctx.HTTPError(http.StatusBadRequest, "repo_id must be 'owner/name'")
		return
	}

	// The token is verified before any repo lookup, and the repo comes from the
	// token's own binding, so every rejection below is one indistinguishable
	// 401: probing can't reveal whether a repo exists or is private. Purpose
	// rules (download-link tokens only for their one file, never for token
	// exchange), scope and archived/mirror write-locks are enforced in
	// AuthorizeBaleClaims. An anonymous principal (read-only, public repo)
	// verifies to (nil user, anonymous=true).
	bearer := strings.TrimPrefix(strings.TrimSpace(req.HubBearer), "Bearer ")
	repository, user, anonymous, err := authorizeCheckAccess(ctx, bearer, req.Repo.RepoID, requestedMode, fileID)
	if err != nil {
		if !isAccessRejection(err) {
			log.Error("Bale check_access: %v", err)
			ctx.HTTPError(http.StatusInternalServerError)
			return
		}
		log.Trace("Bale check_access: bearer rejected for %s: %v", req.Repo.RepoID, err)
		ctx.HTTPError(http.StatusUnauthorized)
		return
	}

	userID := AnonymousUserID
	if !anonymous {
		userID = user.Name
	}

	ctx.Resp.Header().Set("Content-Type", "application/json")
	ctx.Resp.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(ctx.Resp).Encode(CheckAccessResponse{
		UserID: userID,
		RepoID: CanonicalRepoID(repository),
		Owner:  CanonicalOwnerID(repository.OwnerID),
	}); err != nil {
		log.Error("Bale check_access: encode response: %v", err)
	}
}

func authorizeCheckAccess(ctx *context.Context, bearer, repoID string, mode perm_model.AccessMode, fileID string) (*repo_model.Repository, *user_model.User, bool, error) {
	claims, err := lfs.ParseBaleToken(bearer)
	if err != nil {
		return nil, nil, false, util.NewPermissionDeniedErrorf("invalid token")
	}
	repository, err := repo_model.GetRepositoryByID(ctx, claims.RepoID)
	if err != nil {
		return nil, nil, false, err
	}
	if repoRefConflicts(repoID, repository) {
		return nil, nil, false, util.NewPermissionDeniedErrorf("repo_id does not match the token's repository")
	}
	user, anonymous, err := lfs.AuthorizeBaleClaims(ctx, claims, repository, mode, fileID)
	if err != nil {
		return nil, nil, false, err
	}
	if !anonymous && user == nil {
		return nil, nil, false, util.NewPermissionDeniedErrorf("no principal")
	}
	return repository, user, anonymous, nil
}

// isAccessRejection separates a 401 from an internal failure. Internal errors
// can only surface after the JWT verified, so a 500 is no existence oracle.
func isAccessRejection(err error) bool {
	return errors.Is(err, util.ErrPermissionDenied) || repo_model.IsErrRepoNotExist(err) || user_model.IsErrUserNotExist(err)
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
