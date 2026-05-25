// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package dfs

import (
	"errors"
	"fmt"
	"time"

	"code.gitea.io/gitea/modules/setting"

	"github.com/golang-jwt/jwt/v5"
)

// AuthenticateResponse is the JSON payload `git-dfs-authenticate` writes to
// stdout. Mirrors the `git-lfs-authenticate` shape, with `href` pointing at
// xet-server's HF token endpoint rather than gitea's own LFS server.
type AuthenticateResponse struct {
	// Href is the base URL the client should send subsequent CAS / token
	// requests to. Set to the configured xet-server SERVER_URL.
	Href string `json:"href"`
	// Header is appended to those requests; carries the ephemeral bearer.
	Header map[string]string `json:"header"`
	// ExpiresAt is RFC 3339; the client should refresh before then.
	ExpiresAt string `json:"expires_at"`
}

// EphemeralBearerClaims is the JWT shape returned by `git-dfs-authenticate`.
// The bearer is intentionally narrow: it identifies the user gitea already
// authenticated over SSH and a short expiry. It is NOT a xet-server token;
// the client presents it as `hub_bearer` to xet-server's HF token endpoint,
// which then calls back into gitea's /-/dfs/check_access (the M-gitea-3 seam)
// where this same package recognizes the JWT and resolves the user.
//
// Subject (Sub) is the gitea numeric user ID as a string — stable across
// renames, unlike the username.
type EphemeralBearerClaims struct {
	jwt.RegisteredClaims
}

// Issuer string used in JWTs minted here, also matched in ParseEphemeralBearer.
// Distinct from any other gitea JWT (LFS, OAuth2) so a stolen LFS token can
// never be replayed as a DFS bearer.
const ephemeralBearerIssuer = "gitea-dfs"

// MintEphemeralBearer returns a JWT representing "gitea has authenticated
// user `userID` over SSH; this bearer is good for the configured TTL". Used
// by the `git-dfs-authenticate` SSH command.
func MintEphemeralBearer(userID int64) (token string, expiresAt time.Time, err error) {
	if len(setting.DFS.EphemeralJWTSecretBytes) == 0 {
		return "", time.Time{}, errors.New("DFS ephemeral JWT secret is not configured")
	}
	if userID <= 0 {
		return "", time.Time{}, fmt.Errorf("invalid userID %d", userID)
	}
	now := time.Now()
	expiresAt = now.Add(setting.DFS.EphemeralBearerTTL)
	claims := EphemeralBearerClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    ephemeralBearerIssuer,
			Subject:   fmt.Sprintf("%d", userID),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := jwtToken.SignedString(setting.DFS.EphemeralJWTSecretBytes)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("sign DFS ephemeral bearer: %w", err)
	}
	return signed, expiresAt, nil
}

// ParseEphemeralBearer verifies an ephemeral bearer and returns the gitea
// userID it represents. Verifies signature, NBF, EXP, and issuer.
func ParseEphemeralBearer(raw string) (userID int64, err error) {
	if len(setting.DFS.EphemeralJWTSecretBytes) == 0 {
		return 0, errors.New("DFS ephemeral JWT secret is not configured")
	}
	parsed, err := jwt.ParseWithClaims(
		raw,
		&EphemeralBearerClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return setting.DFS.EphemeralJWTSecretBytes, nil
		},
		jwt.WithIssuer(ephemeralBearerIssuer),
	)
	if err != nil {
		return 0, err
	}
	claims, ok := parsed.Claims.(*EphemeralBearerClaims)
	if !ok || !parsed.Valid {
		return 0, errors.New("invalid DFS ephemeral bearer claims")
	}
	var id int64
	if _, err := fmt.Sscanf(claims.Subject, "%d", &id); err != nil || id <= 0 {
		return 0, fmt.Errorf("malformed subject %q in ephemeral bearer", claims.Subject)
	}
	return id, nil
}
