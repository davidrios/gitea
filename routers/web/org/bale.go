// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package org

import (
	"net/http"

	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/templates"
	shared_user "code.gitea.io/gitea/routers/web/shared/user"
	bale_service "code.gitea.io/gitea/services/bale"
	"code.gitea.io/gitea/services/context"
)

const tplSettingsBale templates.TplName = "org/settings/bale"

// Bale renders the per-org bale storage panel using the same shared partial
// the user-settings page uses. Owner-level totals show the dedup savings that
// stack up across the org's repos.
func Bale(ctx *context.Context) {
	if !setting.Bale.Enabled {
		ctx.NotFound(nil)
		return
	}
	ctx.Data["Title"] = ctx.Tr("bale.settings_nav")
	ctx.Data["PageIsOrgSettings"] = true
	ctx.Data["PageIsSettingsBale"] = true

	if _, err := shared_user.RenderUserOrgHeader(ctx); err != nil {
		ctx.ServerError("RenderUserOrgHeader", err)
		return
	}

	if bale_service.UsageAvailable() {
		usage, err := bale_service.GetOwnerUsage(ctx, ctx.ContextUser.Name)
		if err != nil {
			log.Warn("Bale org settings: GetOwnerUsage(%s): %v", ctx.ContextUser.Name, err)
			ctx.Data["BaleUsageError"] = err.Error()
		} else {
			ctx.Data["BaleUsage"] = usage
		}
	}
	ctx.HTML(http.StatusOK, tplSettingsBale)
}
