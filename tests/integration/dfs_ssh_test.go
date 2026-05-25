// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net/http"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	auth_model "code.gitea.io/gitea/models/auth"
	git_model "code.gitea.io/gitea/models/git"
	"code.gitea.io/gitea/modules/json"
	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"
	"code.gitea.io/gitea/services/dfs"
	"code.gitea.io/gitea/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withDFSEnabledOnDisk writes the `[dfs]` block to the test config file so a
// spawned `gitea serv` subprocess reads it, AND mocks the in-process
// settings so the parent test sees the same values. The JWT secret is the
// shared LFS_JWT_SECRET (DFS reuses LFS's token machinery). Returns a
// cleanup that restores both.
func withDFSEnabledOnDisk(t *testing.T, serverURL string, ttl time.Duration) func() {
	t.Helper()
	cfg, err := setting.CfgProvider.PrepareSaving()
	require.NoError(t, err)
	prev := map[string]string{}
	for _, k := range []string{"ENABLED", "SERVER_URL"} {
		prev[k] = cfg.Section("dfs").Key(k).String()
	}
	cfg.Section("dfs").Key("ENABLED").SetValue("true")
	cfg.Section("dfs").Key("SERVER_URL").SetValue(serverURL)
	require.NoError(t, cfg.Save())

	restoreEnabled := test.MockVariableValue(&setting.DFS.Enabled, true)
	restoreURL := test.MockVariableValue(&setting.DFS.ServerURL, serverURL)
	restoreTTL := test.MockVariableValue(&setting.LFS.HTTPAuthExpiry, ttl)

	return func() {
		restoreTTL()
		restoreURL()
		restoreEnabled()
		cfg, err := setting.CfgProvider.PrepareSaving()
		require.NoError(t, err)
		for k, v := range prev {
			cfg.Section("dfs").Key(k).SetValue(v)
		}
		_ = cfg.Save()
	}
}

// sshDFSCommand returns an exec.Cmd that runs the given remote command via
// the test's SSH key and gitea's embedded SSH server.
func sshDFSCommand(keyFile, remoteCmd string) *exec.Cmd {
	return exec.Command("ssh",
		"-p", strconv.Itoa(setting.SSH.ListenPort),
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-o", "IdentitiesOnly=yes",
		"-i", keyFile,
		"git@"+setting.SSH.ListenHost,
		remoteCmd,
	)
}

// Exercises `ssh git@gitea git-dfs-authenticate <repo> <op>` end-to-end
// through gitea's embedded SSH server. The returned bearer must round-trip
// through /-/dfs/check_access so the SSH-issued JWT path matches what
// xet-server will receive.
func TestDFSSSHAuthenticate(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		if _, err := exec.LookPath("ssh"); err != nil {
			t.Skip("ssh not on PATH")
		}

		const xetServerURL = "https://cas.example.test"
		defer withDFSEnabledOnDisk(t, xetServerURL, 5*time.Minute)()

		apiCtx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser)

		withKeyFile(t, "dfs-ssh-key", func(keyFile string) {
			t.Run("CreateUserKey", doAPICreateUserKey(apiCtx, "dfs-test-key", keyFile))

			cmd := sshDFSCommand(keyFile, "git-dfs-authenticate user2/repo1 download")
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			require.NoError(t, cmd.Run(), "ssh stderr: %s", stderr.String())

			var resp git_model.LFSTokenResponse
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &resp), "stdout: %q", stdout.String())
			assert.Equal(t, xetServerURL, resp.Href)
			auth := resp.Header["Authorization"]
			require.True(t, strings.HasPrefix(auth, "Bearer "), "Authorization must be 'Bearer <token>', got %q", auth)
			bearer := strings.TrimPrefix(auth, "Bearer ")
			require.NotEmpty(t, bearer)

			t.Run("BearerRoundTripsThroughCheckAccess", func(t *testing.T) {
				defer tests.PrintCurrentTest(t)()
				body, err := json.Marshal(dfs.CheckAccessRequest{
					HubBearer: bearer,
					Repo: dfs.CheckAccessRepoRef{
						RepoType: "model",
						RepoID:   "user2/repo1",
						Revision: "main",
					},
					Scope: "read",
				})
				require.NoError(t, err)
				req := NewRequestWithBody(t, "POST", "/-/dfs/check_access", bytes.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				resp := MakeRequest(t, req, http.StatusOK)
				var got dfs.CheckAccessResponse
				require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &got))
				assert.Equal(t, "user2", got.UserID)
			})
		})
	})
}

// Bad op should exit non-zero before minting anything.
func TestDFSSSHAuthenticate_BadOp(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		if _, err := exec.LookPath("ssh"); err != nil {
			t.Skip("ssh not on PATH")
		}
		defer withDFSEnabledOnDisk(t, "https://cas.example.test", 5*time.Minute)()

		apiCtx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser)
		withKeyFile(t, "dfs-ssh-key-badop", func(keyFile string) {
			t.Run("CreateUserKey", doAPICreateUserKey(apiCtx, "dfs-test-key-badop", keyFile))
			cmd := sshDFSCommand(keyFile, "git-dfs-authenticate user2/repo1 wat")
			assert.Error(t, cmd.Run(), "expected ssh exit non-zero for unsupported op")
		})
	})
}
