// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"net/http"

	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/dfs"
)

const RouterMockPointCommonDFS = "common-dfs"

// AddOwnerRepoGitDFSRoutes mounts DFS routes under
// /{username}/{reponame}/info/dfs (with optional `.git` suffix).
func AddOwnerRepoGitDFSRoutes(m *web.Router, middlewares ...any) {
	m.Group("/{username}/{reponame}/info/dfs", func() {
		m.Get("", dfs.DiscoveryHandler)
		m.Post("/authenticate", dfs.AuthenticateHTTPHandler)
		m.Any("/*", http.NotFound)
	}, append([]any{web.RouterMockPoint(RouterMockPointCommonDFS)}, middlewares...)...)
}
