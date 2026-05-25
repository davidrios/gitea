// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"net/http"

	"code.gitea.io/gitea/modules/web"
	"code.gitea.io/gitea/services/dfs"
)

const RouterMockPointCommonDFS = "common-dfs"

// AddOwnerRepoGitDFSRoutes mounts the DFS routes under
// `/{username}/{reponame}/info/dfs`. The route group accepts the same `.git`
// suffix on `{reponame}` that the LFS routes do — git clients derive the
// info path by appending to the remote URL.
//
// Today this only mounts the discovery endpoint; transfer-token and
// authz-upstream routes land in M-gitea-3 / M-gitea-4.
func AddOwnerRepoGitDFSRoutes(m *web.Router, middlewares ...any) {
	m.Group("/{username}/{reponame}/info/dfs", func() {
		m.Get("", dfs.DiscoveryHandler)
		m.Any("/*", http.NotFound)
	}, append([]any{web.RouterMockPoint(RouterMockPointCommonDFS)}, middlewares...)...)
}
