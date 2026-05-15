package authing

import (
	"context"
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// signTestToken issues an ES256 JWT with the given claims. Used to drive the
// validator in tests without a real IdP roundtrip beyond the JWKS fetch.
func signTestToken(t *testing.T, priv *ecdsa.PrivateKey, kid string, claims OAuthClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	require.NoError(t, err)
	return signed
}

func newTestAuthTool(issuer string, jwks *JWKSCache) *AuthTool {
	return &AuthTool{
		config: &Config{OAuthIssuer: issuer},
		jwks:   jwks,
	}
}

func TestValidateJWT_HappyPath(t *testing.T) {
	jwk, priv := makeJWKS(t, "kid-happy")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := newTestAuthTool(srv.URL, NewJWKSCache(srv.URL, time.Hour, srv.Client()))
	now := time.Now()
	tok := signTestToken(t, priv, "kid-happy", OAuthClaims{
		ClientID: "demo",
		TenantID: "kiku_app",
		UserType: "user",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    srv.URL,
			Subject:   "user-42",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})

	uid, utype, tenant, err := tool.validateJWT(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "user-42", uid)
	assert.Equal(t, "user", utype)
	assert.Equal(t, "kiku_app", tenant)
}

func TestValidateJWT_WrongIssuerRejected(t *testing.T) {
	jwk, priv := makeJWKS(t, "k1")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := newTestAuthTool(srv.URL, NewJWKSCache(srv.URL, time.Hour, srv.Client()))
	now := time.Now()
	tok := signTestToken(t, priv, "k1", OAuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://evil.com",
			Subject:   "u",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	_, _, _, err := tool.validateJWT(context.Background(), tok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer")
}

func TestValidateJWT_ExpiredRejected(t *testing.T) {
	jwk, priv := makeJWKS(t, "k1")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := newTestAuthTool(srv.URL, NewJWKSCache(srv.URL, time.Hour, srv.Client()))
	now := time.Now()
	tok := signTestToken(t, priv, "k1", OAuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    srv.URL,
			Subject:   "u",
			IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)),
		},
	})
	_, _, _, err := tool.validateJWT(context.Background(), tok)
	require.Error(t, err)
}

func TestValidateJWT_UnknownKIDFails(t *testing.T) {
	jwk, priv := makeJWKS(t, "real-kid")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := newTestAuthTool(srv.URL, NewJWKSCache(srv.URL, time.Hour, srv.Client()))
	now := time.Now()
	tok := signTestToken(t, priv, "ghost-kid", OAuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    srv.URL,
			Subject:   "u",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	_, _, _, err := tool.validateJWT(context.Background(), tok)
	require.Error(t, err)
}

func TestValidateJWT_TamperedSignatureRejected(t *testing.T) {
	jwk, priv := makeJWKS(t, "k1")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := newTestAuthTool(srv.URL, NewJWKSCache(srv.URL, time.Hour, srv.Client()))
	now := time.Now()
	tok := signTestToken(t, priv, "k1", OAuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    srv.URL,
			Subject:   "u",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	// Flip one byte at end (signature segment)
	tampered := tok[:len(tok)-2] + "ZZ"
	_, _, _, err := tool.validateJWT(context.Background(), tampered)
	require.Error(t, err)
}

func TestValidateJWT_NoIssuerPin_AllowsAnyIssuer(t *testing.T) {
	// When config.OAuthIssuer is empty (unusual but supported for backward
	// compat scenarios), validateJWT should not refuse on issuer mismatch.
	// Note: in practice, NewAuthTool only constructs jwks when OAuthIssuer
	// is non-empty, so this case is mostly defensive.
	jwk, priv := makeJWKS(t, "k1")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := &AuthTool{
		config: &Config{}, // empty issuer
		jwks:   NewJWKSCache(srv.URL, time.Hour, srv.Client()),
	}
	now := time.Now()
	tok := signTestToken(t, priv, "k1", OAuthClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "any-issuer",
			Subject:   "u",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	uid, _, _, err := tool.validateJWT(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "u", uid)
}

func TestValidateJWT_MissingJWKSCache(t *testing.T) {
	tool := &AuthTool{config: &Config{}, jwks: nil}
	_, _, _, err := tool.validateJWT(context.Background(), "a.b.c")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS")
}

func TestValidateToken_DispatchesByShape(t *testing.T) {
	// IsJWT detection alone (no IdP needed for this path)
	jwk, priv := makeJWKS(t, "k1")
	srv, _, _ := mockIdP(t, jwk)
	defer srv.Close()

	tool := newTestAuthTool(srv.URL, NewJWKSCache(srv.URL, time.Hour, srv.Client()))

	// JWT token → dispatched to validateJWT
	now := time.Now()
	jwtTok := signTestToken(t, priv, "k1", OAuthClaims{
		ClientID: "demo",
		TenantID: "t1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    srv.URL,
			Subject:   "u-jwt",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
	})
	uid, _, tenant, err := tool.ValidateToken(context.Background(), jwtTok)
	require.NoError(t, err)
	assert.Equal(t, "u-jwt", uid)
	assert.Equal(t, "t1", tenant)

	// Opaque token shape (no dots) — would dispatch to Redis path. Without
	// a Redis client, that path will panic; we just confirm IsJWT is false.
	assert.False(t, IsJWT("opaque-token-no-dots"))
}
