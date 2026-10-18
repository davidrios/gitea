// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bale

import (
	"strconv"
	"strings"

	repo_model "code.gitea.io/gitea/models/repo"
)

// baleforgit-server scopes tokens, file registrations and downloads to the
// repo_id check_access returns, and charges quota/accounting to its `owner`.
// Keying the scope on the repo ID alone keeps it stable across case variants,
// renames and transfers to another owner. On a transfer, usage already counted
// stays with the old owner's historical accounting; new uploads are charged to
// the new owner.
//
// This assumes repo IDs are never reused against the same bale-server data:
// resetting or recreating gitea's database while keeping the bale-server's
// would hand the old repos' files to whichever new repos get the same IDs.

// CanonicalOwnerID is the owner key baleforgit-server bills usage and quotas to.
func CanonicalOwnerID(ownerID int64) string {
	return strconv.FormatInt(ownerID, 10)
}

// CanonicalRepoID is "id/<repoID>".
func CanonicalRepoID(repo *repo_model.Repository) string {
	return "id/" + strconv.FormatInt(repo.ID, 10)
}

// repoRefConflicts reports whether a request's repo_id explicitly names a repo
// other than the token's. Names aren't checked: the scope comes from the
// token's RepoID, and a client may still hold a pre-rename/transfer name. A
// literal owner "id" with a numeric repo name is honored as a name.
func repoRefConflicts(repoID string, repo *repo_model.Repository) bool {
	n, ok := strings.CutPrefix(repoID, "id/")
	if !ok || n == strconv.FormatInt(repo.ID, 10) {
		return false
	}
	if _, err := strconv.ParseInt(n, 10, 64); err != nil {
		return false
	}
	return !(strings.EqualFold(repo.OwnerName, "id") && strings.EqualFold(repo.Name, n))
}
