package authing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JWKSCache holds the public signing keys an IdP exposes via /jwks +
// /.well-known/openid-configuration. Used by AuthTool to verify OAuth
// access tokens (ES256 JWT) without consulting the IdP on every request.
//
// Cache strategy:
//   - First Get() warms by calling Refresh() under lock.
//   - Subsequent Get() returns the cached key for the requested kid.
//   - kid miss triggers a Refresh() (with throttling — at most once per 30s
//     to avoid hammering the IdP under cache poisoning).
//   - Periodic background refresh keyed off Config.JWKSRefreshInterval keeps
//     the cache warm; not required for correctness.
type JWKSCache struct {
	issuer        string
	httpClient    *http.Client
	maxAge        time.Duration
	throttleAfter time.Duration

	mu          sync.RWMutex
	keys        map[string]*ecdsa.PublicKey // kid → ECDSA P-256 public key
	loadedAt    time.Time
	lastRefresh time.Time
}

// NewJWKSCache constructs a cache. issuer must be a fully-qualified URL
// (no trailing slash). httpClient is optional — defaults to a 5s-timeout
// client with no proxies.
func NewJWKSCache(issuer string, maxAge time.Duration, hc *http.Client) *JWKSCache {
	if hc == nil {
		hc = &http.Client{Timeout: 5 * time.Second}
	}
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	return &JWKSCache{
		issuer:        strings.TrimRight(issuer, "/"),
		httpClient:    hc,
		maxAge:        maxAge,
		throttleAfter: 30 * time.Second,
		keys:          make(map[string]*ecdsa.PublicKey),
	}
}

// Get returns the public key for kid, refreshing the cache if necessary.
// Returns ErrUnknownKID after a refresh that still doesn't include the kid.
func (c *JWKSCache) Get(ctx context.Context, kid string) (*ecdsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("jwks: empty kid")
	}
	c.mu.RLock()
	key, ok := c.keys[kid]
	stale := time.Since(c.loadedAt) > c.maxAge
	c.mu.RUnlock()

	if ok && !stale {
		return key, nil
	}

	// Either kid miss or cache stale — refresh under lock with throttle.
	if err := c.maybeRefresh(ctx); err != nil {
		// If we already have *some* key for this kid, prefer stale over fail.
		if ok {
			return key, nil
		}
		return nil, err
	}

	c.mu.RLock()
	key, ok = c.keys[kid]
	c.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("jwks: kid %q not found after refresh", kid)
	}
	return key, nil
}

// maybeRefresh calls Refresh() if the throttle window has elapsed.
func (c *JWKSCache) maybeRefresh(ctx context.Context) error {
	c.mu.Lock()
	if time.Since(c.lastRefresh) < c.throttleAfter {
		c.mu.Unlock()
		return nil
	}
	c.lastRefresh = time.Now()
	c.mu.Unlock()
	return c.Refresh(ctx)
}

// Refresh fetches the discovery document then the JWKS. Replaces the cached
// keys atomically. Caller is responsible for throttling — use maybeRefresh()
// in hot paths.
func (c *JWKSCache) Refresh(ctx context.Context) error {
	jwksURI, err := c.fetchJWKSURI(ctx)
	if err != nil {
		return err
	}
	keys, err := c.fetchJWKS(ctx, jwksURI)
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.keys = keys
	c.loadedAt = time.Now()
	c.mu.Unlock()
	return nil
}

// fetchJWKSURI hits /.well-known/openid-configuration and pulls jwks_uri.
// We could hardcode <issuer>/oauth/jwks but the discovery doc is the IdP's
// own statement of where its keys live — preferred for resilience.
func (c *JWKSCache) fetchJWKSURI(ctx context.Context) (string, error) {
	url := c.issuer + "/.well-known/openid-configuration"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("jwks: fetch discovery %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("jwks: discovery %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("jwks: read discovery body: %w", err)
	}
	var doc struct {
		JwksURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("jwks: parse discovery: %w", err)
	}
	if doc.JwksURI == "" {
		return "", fmt.Errorf("jwks: discovery has no jwks_uri")
	}
	return doc.JwksURI, nil
}

// fetchJWKS pulls the JWKS document and parses ES256 (P-256) keys. Other
// kty/alg combinations are skipped silently — we only verify ES256 tokens
// since that's what the IdP issues.
func (c *JWKSCache) fetchJWKS(ctx context.Context, url string) (map[string]*ecdsa.PublicKey, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("jwks: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("jwks: %s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("jwks: read body: %w", err)
	}
	return ParseJWKS(body)
}

// ParseJWKS turns a JWKS JSON body into a kid → public key map. Exported
// so tests can build cache state without HTTP.
func ParseJWKS(body []byte) (map[string]*ecdsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Kid string `json:"kid"`
			Crv string `json:"crv"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwks: parse: %w", err)
	}
	out := make(map[string]*ecdsa.PublicKey)
	for _, k := range doc.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			continue
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			continue
		}
		pub := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}
		// Sanity: must be on the curve
		if !elliptic.P256().IsOnCurve(pub.X, pub.Y) {
			continue
		}
		out[k.Kid] = pub
	}
	return out, nil
}
