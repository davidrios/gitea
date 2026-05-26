// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"net/http"

	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/bale"
)

const RouterMockPointCommonBale = "common-bale"

// AddOwnerRepoGitBaleRoutes mounts Bale routes under
// /{username}/{reponame}/info/bale (with optional `.git` suffix).
func AddOwnerRepoGitBaleRoutes(m *web.Router, middlewares ...any) {
	m.Group("/{username}/{reponame}/info/bale", func() {
		m.Get("", bale.DiscoveryHandler)
		m.Post("/authenticate", bale.AuthenticateHTTPHandler)
		m.Any("/*", http.NotFound)
	}, append([]any{web.RouterMockPoint(RouterMockPointCommonBale)}, middlewares...)...)
}
