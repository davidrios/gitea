// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"net/url"
	"strings"

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
	}
}
