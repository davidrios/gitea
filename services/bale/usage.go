// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bale

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"code.gitea.io/gitea/modules/httplib"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
)

// OwnerUsage mirrors crates/bale-server-wire's OwnerUsageResponse. QuotaBytes
// is a pointer so the JSON `null` (unlimited) round-trips distinctly from 0.
// All byte counts are int64 so they feed gitea's `FileSize` helper directly.
type OwnerUsage struct {
	Owner             string `json:"owner"`
	RawBytes          int64  `json:"raw_bytes"`
	StoredBytes       int64  `json:"stored_bytes"`
	DedupSavingsBytes int64  `json:"dedup_savings_bytes"`
	QuotaBytes        *int64 `json:"quota_bytes"`
}

// HasQuota reports whether the owner has a quota configured (server default
// or per-owner override). Go templates can't deref *int64 directly, so the
// shared owner-panel partial uses this + [OwnerUsage.Quota] instead.
func (u *OwnerUsage) HasQuota() bool { return u.QuotaBytes != nil }

// Quota returns the quota in bytes, or 0 if unlimited (check HasQuota first).
func (u *OwnerUsage) Quota() int64 {
	if u.QuotaBytes == nil {
		return 0
	}
	return *u.QuotaBytes
}

// RepoUsage mirrors crates/bale-server-wire's RepoUsageResponse.
type RepoUsage struct {
	RepoID            string `json:"repo_id"`
	RawBytes          int64  `json:"raw_bytes"`
	StoredBytes       int64  `json:"stored_bytes"`
	DedupSavingsBytes int64  `json:"dedup_savings_bytes"`
}

// UsageAvailable reports whether the usage endpoints can be called — the bale
// server is enabled and an admin token is configured. Callers should check
// this before calling so they can hide their UI cleanly when usage is
// off-limits, instead of needing to interpret a sentinel return.
func UsageAvailable() bool {
	return setting.Bale.Enabled && setting.Bale.AdminToken != ""
}

// GetOwnerUsage calls GET /v1/usage/{owner}. Precondition: [UsageAvailable].
func GetOwnerUsage(ctx context.Context, ownerName string) (*OwnerUsage, error) {
	var out OwnerUsage
	if err := getJSON(ctx, "/v1/usage/"+url.PathEscape(ownerName), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRepoUsage calls GET /v1/usage/repo/{owner}/{repo}. Precondition: [UsageAvailable].
func GetRepoUsage(ctx context.Context, ownerName, repoName string) (*RepoUsage, error) {
	var out RepoUsage
	path := "/v1/usage/repo/" + url.PathEscape(ownerName) + "/" + url.PathEscape(repoName)
	if err := getJSON(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// getJSON runs an authenticated GET against `path` on the bale server and
// decodes the response into `out`. The 5s read/write timeout matches what's
// reasonable for a synchronous settings-page render.
func getJSON(ctx context.Context, path string, out any) error {
	resp, err := httplib.NewRequest(setting.Bale.InternalServerURL+path, http.MethodGet).
		SetContext(ctx).
		SetReadWriteTimeout(5*time.Second).
		Header("Authorization", "Bearer "+setting.Bale.AdminToken).
		Response()
	if err != nil {
		return fmt.Errorf("bale request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Cap how much of the error body we surface — the server returns small
		// JSON error blobs, but a misbehaving proxy could send a megabyte page.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("bale: status %d: %s", resp.StatusCode, body)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("bale: decode: %w", err)
	}
	return nil
}
