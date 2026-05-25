// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"strings"
	"testing"
	"time"

	"code.gitea.io/gitea/modules/setting"
	"code.gitea.io/gitea/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEphemeralBearerRoundTrip(t *testing.T) {
	defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("test-secret-32-bytes-pad-xxxxxxx"))()
	defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, time.Hour)()

	tok, exp, err := MintEphemeralBearer(42)
	require.NoError(t, err)
	assert.True(t, exp.After(time.Now()), "ExpiresAt must be in the future")
	assert.True(t, strings.Contains(tok, "."), "JWT contains a dot — used by check_access to dispatch to JWT path")

	id, err := ParseEphemeralBearer(tok)
	require.NoError(t, err)
	assert.EqualValues(t, 42, id)
}

func TestParseEphemeralBearer_RejectsForeignSecret(t *testing.T) {
	defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("real-secret-xxxxxxxxxxxxxxxxxxxx"))()
	defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, time.Hour)()
	tok, _, err := MintEphemeralBearer(42)
	require.NoError(t, err)

	defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("different-secret-yyyyyyyyyyyyyyyy"))()
	_, err = ParseEphemeralBearer(tok)
	assert.Error(t, err)
}

func TestParseEphemeralBearer_RejectsExpired(t *testing.T) {
	defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("test-secret-32-bytes-pad-xxxxxxx"))()
	// Negative TTL → already-expired token.
	defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, -time.Minute)()

	tok, _, err := MintEphemeralBearer(42)
	require.NoError(t, err)
	_, err = ParseEphemeralBearer(tok)
	assert.Error(t, err, "expired tokens must be rejected")
}

func TestMintEphemeralBearer_RejectsZeroUserID(t *testing.T) {
	defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte("test-secret-32-bytes-pad-xxxxxxx"))()
	defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, time.Hour)()
	_, _, err := MintEphemeralBearer(0)
	assert.Error(t, err)
}

func TestMintEphemeralBearer_RequiresSecret(t *testing.T) {
	defer test.MockVariableValue(&setting.DFS.EphemeralJWTSecretBytes, []byte(nil))()
	defer test.MockVariableValue(&setting.DFS.EphemeralBearerTTL, time.Hour)()
	_, _, err := MintEphemeralBearer(1)
	assert.Error(t, err)
}
