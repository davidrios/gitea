// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"net/url"
	"strings"

	"code.gitea.io/gitea/modules/log"
)

// DFS holds the git-dfs integration config. Bytes live on a separate
// xet-server; gitea handles URL discovery and upstream authz.
var DFS = struct {
	Enabled   bool   `ini:"ENABLED"`
	ServerURL string `ini:"SERVER_URL"`
}{}

func loadDFSFrom(rootCfg ConfigProvider) {
	mustMapSetting(rootCfg, "dfs", &DFS)
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
	// DFS reuses the LFS JWT secret. LFS's loader skipped secret generation
	// when StartServer is off — do it now so DFS can mint/verify standalone.
	if InstallLock && len(LFS.JWTSecretBytes) == 0 {
		if err := loadLFSJWTSecret(rootCfg); err != nil {
			log.Error("[dfs] failed to load shared LFS JWT secret: %v. Disabling DFS.", err)
			DFS.Enabled = false
		}
	}
}
