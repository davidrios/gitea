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

const tplSettingsBale templates.TplName = "user/settings/bale"

// Bale renders the per-user bale storage panel — total uncompressed, actually
// stored, savings, and quota — aggregated across all repos the user owns. The
// shared owner-panel partial is also used by the org settings handler.
func Bale(ctx *context.Context) {
	if !setting.Bale.Enabled {
		ctx.NotFound(nil)
		return
	}
	ctx.Data["Title"] = ctx.Tr("bale.settings_nav")
	ctx.Data["PageIsSettingsBale"] = true

	if bale_service.UsageAvailable() {
		usage, err := bale_service.GetOwnerUsage(ctx, ctx.Doer.Name)
		if err != nil {
			log.Warn("Bale user settings: GetOwnerUsage(%s): %v", ctx.Doer.Name, err)
			ctx.Data["BaleUsageError"] = err.Error()
		} else {
			ctx.Data["BaleUsage"] = usage
		}
	}
	ctx.HTML(http.StatusOK, tplSettingsBale)
}
