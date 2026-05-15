package authing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// OAuthClaims mirrors the access-token claims the IdP issues (RFC 9068
// shape + tenant_id/user_type extensions). Mirror of userLogin's
// OAuthAccessTokenClaims so authing can decode without depending on
// userLogin.
type OAuthClaims struct {
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`
	UserType string `json:"user_type,omitempty"`
	jwt.RegisteredClaims
}

// IsJWT returns true iff the supplied token has the compact JWT shape
// (three base64url segments separated by dots). Used by ValidateToken to
// dispatch between JWT and Redis paths without making a guess that costs
// a network round trip.
func IsJWT(token string) bool {
	if token == "" {
		return false
	}
	if strings.Count(token, ".") != 2 {
		return false
	}
	// Defensive: each segment should be non-empty.
	for _, seg := range strings.Split(token, ".") {
		if seg == "" {
			return false
		}
	}
	return true
}

// validateJWT verifies an ES256 access token against the JWKS cache and
// returns the embedded user/tenant identity. The caller should only invoke
// this after IsJWT(token) returns true and after JWKSCache is initialized.
func (s *AuthTool) validateJWT(ctx context.Context, token string) (userID, userType, tenantID string, err error) {
	if s.jwks == nil {
		return "", "", "", errors.New("jwt: JWKS cache not initialized — set Config.OAuthIssuer")
	}
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"ES256"}),
		jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(),
	)
	claims := &OAuthClaims{}
	tok, err := parser.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kidVal, _ := t.Header["kid"].(string)
		if kidVal == "" {
			return nil, errors.New("jwt: missing kid")
		}
		pub, err := s.jwks.Get(ctx, kidVal)
		if err != nil {
			return nil, fmt.Errorf("jwt: get jwks key: %w", err)
		}
		return pub, nil
	})
	if err != nil {
		return "", "", "", err
	}
	if !tok.Valid {
		return "", "", "", errors.New("jwt: token invalid")
	}
	// Issuer pinning — refuse tokens claimed by another IdP. Empty issuer
	// in cache means caller didn't pin (allowed for backward compat).
	if s.config.OAuthIssuer != "" {
		expIss := strings.TrimRight(s.config.OAuthIssuer, "/")
		gotIss := strings.TrimRight(claims.Issuer, "/")
		if gotIss != expIss {
			return "", "", "", fmt.Errorf("jwt: issuer %q != expected %q", gotIss, expIss)
		}
	}
	// Defensive: the registered claims library validates exp, but be
	// explicit about not-before too.
	if claims.NotBefore != nil && claims.NotBefore.After(time.Now()) {
		return "", "", "", errors.New("jwt: not yet valid (nbf)")
	}
	if claims.Subject == "" {
		return "", "", "", errors.New("jwt: missing sub")
	}
	uType := claims.UserType
	if uType == "" {
		uType = "user"
	}
	return claims.Subject, uType, claims.TenantID, nil
}
