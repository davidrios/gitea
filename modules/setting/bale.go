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
var Bale = struct {
	Enabled   bool   `ini:"ENABLED"`
	ServerURL string `ini:"SERVER_URL"`
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
	// Bale reuses the LFS JWT secret. LFS's loader skipped secret generation
	// when StartServer is off — do it now so Bale can mint/verify standalone.
	if InstallLock && len(LFS.JWTSecretBytes) == 0 {
		if err := loadLFSJWTSecret(rootCfg); err != nil {
			log.Error("[bale] failed to load shared LFS JWT secret: %v. Disabling Bale.", err)
			Bale.Enabled = false
		}
	}
}
