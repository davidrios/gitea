// Copyright 2014 The Gogs Authors. All rights reserved.
// Copyright 2018 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"path"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	git_model "code.gitea.io/gitea/models/git"
	"code.gitea.io/gitea/modules/bale"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/httpcache"
	"code.gitea.io/gitea/modules/httplib"
	"code.gitea.io/gitea/modules/lfs"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/storage"
	"code.gitea.io/gitea/routers/common"
	bale_service "code.gitea.io/gitea/services/bale"
	"code.gitea.io/gitea/services/context"
)

func checkDownloadTokenScope(ctx *context.Context) bool {
	context.CheckRepoScopedToken(ctx, ctx.Repo.Repository, auth_model.Read)
	return !ctx.Written()
}

// ServeBlobOrLFS download a git.Blob redirecting to LFS if necessary
func ServeBlobOrLFS(ctx *context.Context, blob *git.Blob, lastModified *time.Time) error {
	if httpcache.HandleGenericETagPrivateCache(ctx.Req, ctx.Resp, `"`+blob.ID.String()+`"`, lastModified) {
		return nil
	}

	// Read up to bale.MetaFileMaxSize so both LFS (~1024 cap) and Bale (~4096 cap)
	// pointers fit in a single read.
	pointerBuf, err := blob.GetBlobBytes(bale.MetaFileMaxSize)
	if err != nil {
		return err
	}

	if setting.Bale.Enabled {
		if balePtr, err := bale.ReadPointerFromBuffer(pointerBuf); err == nil {
			redirectURL, err := bale_service.BuildDownloadRedirectURL(balePtr, ctx.Repo.Repository, ctx.Doer, path.Base(ctx.Repo.TreePath))
			if err != nil {
				log.Error("Bale download: build redirect URL: %v", err)
				return err
			}
			ctx.Redirect(redirectURL)
			return nil
		}
	}

	pointer, _ := lfs.ReadPointerFromBuffer(pointerBuf)
	if pointer.IsValid() {
		meta, _ := git_model.GetLFSMetaObjectByOid(ctx, ctx.Repo.Repository.ID, pointer.Oid)
		if meta == nil {
			return common.ServeBlob(ctx.Base, ctx.Repo.Repository, ctx.Repo.TreePath, blob, lastModified)
		}
		if httpcache.HandleGenericETagPrivateCache(ctx.Req, ctx.Resp, `"`+pointer.Oid+`"`, meta.UpdatedUnix.AsTimePtr()) {
			return nil
		}

		if setting.LFS.Storage.ServeDirect() {
			// If we have a signed url (S3, object storage, blob storage), redirect to this directly.
			u, err := storage.LFS.ServeDirectURL(pointer.RelativePath(), blob.Name(), ctx.Req.Method, nil)
			if u != nil && err == nil {
				ctx.Redirect(u.String())
				return nil
			}
		}

		lfsDataFile, err := lfs.ReadMetaObject(meta.Pointer)
		if err != nil {
			return err
		}
		defer lfsDataFile.Close()
		httplib.ServeUserContentByFile(ctx.Req, ctx.Resp, lfsDataFile, httplib.ServeHeaderOptions{Filename: ctx.Repo.TreePath})
		return nil
	}

	return common.ServeBlob(ctx.Base, ctx.Repo.Repository, ctx.Repo.TreePath, blob, lastModified)
}

func getBlobForEntry(ctx *context.Context) (*git.Blob, *time.Time) {
	entry, err := ctx.Repo.Commit.GetTreeEntryByPath(ctx.Repo.TreePath)
	if err != nil {
		if git.IsErrNotExist(err) {
			ctx.NotFound(err)
		} else {
			ctx.ServerError("GetTreeEntryByPath", err)
		}
		return nil, nil
	}

	if entry.IsDir() || entry.IsSubModule() {
		ctx.NotFound(nil)
		return nil, nil
	}

	latestCommit, err := ctx.Repo.GitRepo.GetTreePathLatestCommit(ctx.Repo.Commit.ID.String(), ctx.Repo.TreePath)
	if err != nil {
		ctx.ServerError("GetTreePathLatestCommit", err)
		return nil, nil
	}
	lastModified := &latestCommit.Committer.When

	return entry.Blob(), lastModified
}

// SingleDownload download a file by repos path
func SingleDownload(ctx *context.Context) {
	if !checkDownloadTokenScope(ctx) {
		return
	}

	blob, lastModified := getBlobForEntry(ctx)
	if blob == nil {
		return
	}

	if err := common.ServeBlob(ctx.Base, ctx.Repo.Repository, ctx.Repo.TreePath, blob, lastModified); err != nil {
		ctx.ServerError("ServeBlob", err)
	}
}

// SingleDownloadOrLFS download a file by repos path redirecting to LFS if necessary
func SingleDownloadOrLFS(ctx *context.Context) {
	if !checkDownloadTokenScope(ctx) {
		return
	}

	blob, lastModified := getBlobForEntry(ctx)
	if blob == nil {
		return
	}

	if err := ServeBlobOrLFS(ctx, blob, lastModified); err != nil {
		ctx.ServerError("ServeBlobOrLFS", err)
	}
}

// DownloadByID download a file by sha1 ID
func DownloadByID(ctx *context.Context) {
	if !checkDownloadTokenScope(ctx) {
		return
	}

	blob, err := ctx.Repo.GitRepo.GetBlob(ctx.PathParam("sha"))
	if err != nil {
		if git.IsErrNotExist(err) {
			ctx.NotFound(nil)
		} else {
			ctx.ServerError("GetBlob", err)
		}
		return
	}
	if err = common.ServeBlob(ctx.Base, ctx.Repo.Repository, ctx.Repo.TreePath, blob, nil); err != nil {
		ctx.ServerError("ServeBlob", err)
	}
}

// DownloadByIDOrLFS download a file by sha1 ID taking account of LFS
func DownloadByIDOrLFS(ctx *context.Context) {
	if !checkDownloadTokenScope(ctx) {
		return
	}

	blob, err := ctx.Repo.GitRepo.GetBlob(ctx.PathParam("sha"))
	if err != nil {
		if git.IsErrNotExist(err) {
			ctx.NotFound(nil)
		} else {
			ctx.ServerError("GetBlob", err)
		}
		return
	}
	if err = ServeBlobOrLFS(ctx, blob, nil); err != nil {
		ctx.ServerError("ServeBlob", err)
	}
}
