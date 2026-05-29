// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"net/url"
	"strings"

	"code.gitea.io/gitea/modules/log"
)

// Bale holds the git-bale integration config. Bytes live on a separate
// baleforgit-server; gitea handles URL discovery and upstream authz.
//
// ServerURL is the public/external address handed to clients (filter discovery,
// auth Href, browser download redirects). InternalServerURL is the address gitea
// itself dials for server-to-server calls (usage stats); it falls back to
// ServerURL when unset, so a split is only needed when the two differ (e.g. a
// cluster-internal hostname that browsers can't resolve).
var Bale = struct {
	Enabled           bool   `ini:"ENABLED"`
	ServerURL         string `ini:"SERVER_URL"`
	InternalServerURL string `ini:"INTERNAL_SERVER_URL"`
	AdminToken        string `ini:"ADMIN_TOKEN"`
}{}

func loadBaleFrom(rootCfg ConfigProvider) {
	mustMapSetting(rootCfg, "bale", &Bale)
	if !Bale.Enabled {
		return
	}
	Bale.ServerURL = strings.TrimRight(Bale.ServerURL, "/")
	if Bale.ServerURL == "" {
		log.Warn("[bale] ENABLED=true but SERVER_URL is empty; clients will not be able to discover the CAS server. Disabling Bale.")
		Bale.Enabled = false
		return
	}
	if _, err := url.Parse(Bale.ServerURL); err != nil {
		log.Warn("[bale] SERVER_URL %q is not a valid URL: %v. Disabling Bale.", Bale.ServerURL, err)
		Bale.Enabled = false
		return
	}
	Bale.InternalServerURL = strings.TrimRight(Bale.InternalServerURL, "/")
	if Bale.InternalServerURL == "" {
		Bale.InternalServerURL = Bale.ServerURL
	} else if _, err := url.Parse(Bale.InternalServerURL); err != nil {
		log.Warn("[bale] INTERNAL_SERVER_URL %q is not a valid URL: %v. Falling back to SERVER_URL.", Bale.InternalServerURL, err)
		Bale.InternalServerURL = Bale.ServerURL
	}
	Bale.AdminToken = strings.TrimSpace(Bale.AdminToken)
	if Bale.AdminToken == "" {
		// Not fatal — only the repo-settings size panel needs this. Bale auth
		// + uploads still work, but the panel hides itself.
		log.Info("[bale] ADMIN_TOKEN unset; the repo-settings storage panel will be hidden")
	}
	// Bale reuses the LFS JWT secret. LFS's loader skipped secret generation
	// when StartServer is off — do it now so Bale can mint/verify standalone.
	if InstallLock && len(LFS.JWTSecretBytes) == 0 {
		if err := loadLFSJWTSecret(rootCfg); err != nil {
			log.Error("[bale] failed to load shared LFS JWT secret: %v. Disabling Bale.", err)
			Bale.Enabled = false
		}
	}
}
