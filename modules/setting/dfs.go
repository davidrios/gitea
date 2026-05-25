// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"code.gitea.io/gitea/modules/generate"
	"code.gitea.io/gitea/modules/log"
)

// DFS holds the server-side configuration for the git-dfs integration.
// Unlike LFS, gitea does NOT host the object bytes — they live on a separate
// xet-server. Gitea's role is authz upstream + URL discovery.
//
// Pairs with the `[dfs]` section in app.ini.
var DFS = struct {
	// Enabled gates the discovery endpoint (and all later DFS routes). If
	// false, gitea behaves as if DFS doesn't exist.
	Enabled bool `ini:"ENABLED"`
	// ServerURL is the public base URL of the xet-server the client should
	// hit for CAS operations. Returned verbatim from the discovery endpoint.
	ServerURL string `ini:"SERVER_URL"`
	// EphemeralBearerTTL controls how long an SSH-issued ephemeral bearer
	// (the JWT returned by `git-dfs-authenticate`) stays valid before the
	// client has to re-handshake. Default 24h.
	EphemeralBearerTTL time.Duration `ini:"EPHEMERAL_BEARER_TTL"`
	// EphemeralJWTSecretBytes is the HMAC key gitea uses to sign ephemeral
	// bearers. Auto-generated on first run if absent; not exposed via INI.
	EphemeralJWTSecretBytes []byte `ini:"-"`
}{}

func loadDFSFrom(rootCfg ConfigProvider) {
	mustMapSetting(rootCfg, "dfs", &DFS)
	if DFS.EphemeralBearerTTL == 0 {
		DFS.EphemeralBearerTTL = 24 * time.Hour
	}
	if !DFS.Enabled {
		return
	}
	DFS.ServerURL = strings.TrimRight(DFS.ServerURL, "/")
	if DFS.ServerURL == "" {
		log.Warn("[dfs] ENABLED=true but SERVER_URL is empty; clients will not be able to discover the CAS server. Disabling DFS.")
		DFS.Enabled = false
		return
	}
	if _, err := url.Parse(DFS.ServerURL); err != nil {
		log.Warn("[dfs] SERVER_URL %q is not a valid URL: %v. Disabling DFS.", DFS.ServerURL, err)
		DFS.Enabled = false
		return
	}
	if err := loadDFSEphemeralJWTSecret(rootCfg); err != nil {
		log.Error("[dfs] failed to load ephemeral JWT secret: %v. Disabling DFS.", err)
		DFS.Enabled = false
	}
}

// loadDFSEphemeralJWTSecret resolves the HMAC key used to sign SSH-issued
// ephemeral bearers. Mirrors LFS_JWT_SECRET's bootstrap: read from
// `[dfs].EPHEMERAL_JWT_SECRET_URI` or `EPHEMERAL_JWT_SECRET`, generate +
// persist into the config file on first run, never rotate silently.
func loadDFSEphemeralJWTSecret(rootCfg ConfigProvider) error {
	if !InstallLock {
		// Mirror the LFS bootstrap: don't churn the config file during the
		// pre-install phase.
		return nil
	}
	secretBase64 := loadSecret(rootCfg.Section("dfs"), "EPHEMERAL_JWT_SECRET_URI", "EPHEMERAL_JWT_SECRET")
	bytes, err := generate.DecodeJwtSecretBase64(secretBase64)
	if err != nil {
		bytes, secretBase64 = generate.NewJwtSecretWithBase64()
		saveCfg, err := rootCfg.PrepareSaving()
		if err != nil {
			return fmt.Errorf("error preparing config save for DFS ephemeral secret: %w", err)
		}
		rootCfg.Section("dfs").Key("EPHEMERAL_JWT_SECRET").SetValue(secretBase64)
		saveCfg.Section("dfs").Key("EPHEMERAL_JWT_SECRET").SetValue(secretBase64)
		if err := saveCfg.Save(); err != nil {
			return fmt.Errorf("error saving DFS ephemeral secret to config: %w", err)
		}
	}
	DFS.EphemeralJWTSecretBytes = bytes
	return nil
}
