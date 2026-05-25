// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package git

const (
	CmdVerbUploadPack      = "git-upload-pack"
	CmdVerbUploadArchive   = "git-upload-archive"
	CmdVerbReceivePack     = "git-receive-pack"
	CmdVerbLfsAuthenticate = "git-lfs-authenticate"
	CmdVerbLfsTransfer     = "git-lfs-transfer"
	// CmdVerbDfsAuthenticate mirrors `git-lfs-authenticate` for the git-dfs
	// integration. There is no transfer verb because, unlike LFS, gitea is
	// not the byte store — the client talks to xet-server directly after
	// receiving the ephemeral bearer this command returns.
	CmdVerbDfsAuthenticate = "git-dfs-authenticate"

	CmdSubVerbLfsUpload   = "upload"
	CmdSubVerbLfsDownload = "download"
)

func IsAllowedVerbForServe(verb string) bool {
	switch verb {
	case CmdVerbUploadPack,
		CmdVerbUploadArchive,
		CmdVerbReceivePack,
		CmdVerbLfsAuthenticate,
		CmdVerbLfsTransfer,
		CmdVerbDfsAuthenticate:
		return true
	}
	return false
}

func IsAllowedVerbForServeLfs(verb string) bool {
	switch verb {
	case CmdVerbLfsAuthenticate,
		CmdVerbLfsTransfer:
		return true
	}
	return false
}
