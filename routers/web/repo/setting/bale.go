// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"net/http"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/templates"
	bale_service "code.gitea.io/gitea/services/bale"
	"code.gitea.io/gitea/services/context"
)

const tplSettingsBale templates.TplName = "repo/settings/bale"

// Bale shows the per-repo storage usage panel, similar to the LFS panel. The
// numbers come from baleforgit-server's /v1/usage/repo endpoint; we surface
// the raw (no-dedup) size so users see the full footprint of files they've
// pushed via git-bale, even when sibling repos under the same owner share
// chunks.
func Bale(ctx *context.Context) {
	if !setting.Bale.Enabled {
		ctx.NotFound(nil)
		return
	}
	ctx.Data["Title"] = ctx.Tr("repo.settings.bale")
	ctx.Data["PageIsSettingsBale"] = true

	// Template branches on which of {BaleUsage, BaleUsageError, neither} is
	// set; "neither" surfaces the "admin token unconfigured" message.
	if bale_service.UsageAvailable() {
		usage, err := bale_service.GetRepoUsage(ctx, ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name)
		if err != nil {
			// Surface the failure inline rather than 500'ing the whole
			// settings page — the remote bale-server being temporarily
			// unreachable shouldn't break repo administration.
			log.Warn("Bale settings: GetRepoUsage(%s/%s): %v", ctx.Repo.Repository.OwnerName, ctx.Repo.Repository.Name, err)
			ctx.Data["BaleUsageError"] = err.Error()
		} else {
			ctx.Data["BaleUsage"] = usage
		}
	}

	ctx.HTML(http.StatusOK, tplSettingsBale)
}
