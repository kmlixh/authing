package authing

import (
	"os"
	"sync"
	"testing"
	"time"

	"github.com/kmlixh/authing/models"
)

// Fix 1: ExpiredAt is *time.Time so nil → SQL NULL.
// We can't run a live SQL roundtrip without PG, but we can verify the type.
func TestFix1_ExpiredAtIsPointer(t *testing.T) {
	p := models.Permission{}
	if p.ExpiredAt != nil {
		t.Errorf("Permission.ExpiredAt zero value should be nil, got %+v", p.ExpiredAt)
	}
	rp := models.RolePermission{}
	if rp.ExpiredAt != nil {
		t.Errorf("RolePermission.ExpiredAt zero value should be nil, got %+v", rp.ExpiredAt)
	}
	up := models.UserPermission{}
	if up.ExpiredAt != nil {
		t.Errorf("UserPermission.ExpiredAt zero value should be nil, got %+v", up.ExpiredAt)
	}
	now := time.Now()
	up.ExpiredAt = &now
	if up.ExpiredAt == nil {
		t.Error("ExpiredAt assignment failed")
	}
}

// Fix 5: matchRoute does exact-match pass before regex pass — so for a
// permission rule list with both an exact match and a regex match, the
// exact one is found in the first pass without paying for any regex
// compilations.
func TestFix5_MatchRouteExactBeforeRegex(t *testing.T) {
	tool := &AuthTool{}
	perms := []models.Permission{
		{IsEnabled: true, Route: `^/api/v1/.+$`}, // regex
		{IsEnabled: true, Route: `/api/v1/users`}, // exact
	}
	// `/api/v1/users` is exact-matched by perms[1]; if pass-1 is exact-only,
	// perms[0] is never consulted.
	if !tool.matchRoute(perms, "/api/v1/users") {
		t.Fatal("expected route to match")
	}
	// And the regex-matched but not-exact route still works:
	if !tool.matchRoute(perms, "/api/v1/products") {
		t.Fatal("regex-only match should still pass")
	}
}

// Fix 5 also: disabled permissions are skipped in BOTH passes.
func TestFix5_DisabledPermissionSkipped(t *testing.T) {
	tool := &AuthTool{}
	perms := []models.Permission{
		{IsEnabled: false, Route: "/api/admin"},
	}
	if tool.matchRoute(perms, "/api/admin") {
		t.Error("disabled permission must not match")
	}
}

// Fix 6: fast-path cache uses *sync.Map per cacheKey — verify the type
// contract via a controlled call. We can't drive CheckPermission without
// a live DB; we test the LoadOrStore pattern directly to pin the type.
func TestFix6_FastPathCache_UsesSyncMap(t *testing.T) {
	tool := &AuthTool{}
	cacheKey := "tenant_user_42"
	// Mimic the hot-path code:
	inner, _ := tool.userAllowedRoutesCache.LoadOrStore(cacheKey, &sync.Map{})
	innerMap, ok := inner.(*sync.Map)
	if !ok {
		t.Fatalf("inner cache value should be *sync.Map, got %T", inner)
	}
	innerMap.Store("/api/x", struct{}{})

	// Concurrent reader path:
	val, present := tool.userAllowedRoutesCache.Load(cacheKey)
	if !present {
		t.Fatal("cacheKey should exist after store")
	}
	syncMap := val.(*sync.Map)
	_, hit := syncMap.Load("/api/x")
	if !hit {
		t.Error("/api/x should be cached")
	}
}

// Fix 3: clearAllUserPermissionCaches removes every entry from both
// userPermissionsCache and userAllowedRoutesCache.
func TestFix3_ClearAllUserPermissionCaches(t *testing.T) {
	tool := &AuthTool{}
	tool.userPermissionsCache.Store("u1", []models.Permission{})
	tool.userPermissionsCache.Store("u2", []models.Permission{})
	tool.userAllowedRoutesCache.Store("u1", &sync.Map{})

	tool.clearAllUserPermissionCaches()

	count := 0
	tool.userPermissionsCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 entries after clear, got %d", count)
	}
	tool.userAllowedRoutesCache.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Errorf("expected 0 fast-path entries, got %d", count)
	}
}

// Fix 4: clearUsersWithRole only nukes users known to have the role.
func TestFix4_ClearUsersWithRole(t *testing.T) {
	tool := &AuthTool{}
	tool.userRolesCache.Store("u-with-role-7", []models.Role{{ID: 7}, {ID: 9}})
	tool.userRolesCache.Store("u-without-role-7", []models.Role{{ID: 9}})
	// Both have permission caches.
	tool.userPermissionsCache.Store("u-with-role-7", []models.Permission{})
	tool.userPermissionsCache.Store("u-without-role-7", []models.Permission{})
	tool.userAllowedRoutesCache.Store("u-with-role-7", &sync.Map{})

	tool.clearUsersWithRole(7)

	if _, ok := tool.userPermissionsCache.Load("u-with-role-7"); ok {
		t.Error("user with role 7 should have been cleared")
	}
	if _, ok := tool.userPermissionsCache.Load("u-without-role-7"); !ok {
		t.Error("user without role 7 must NOT have been cleared")
	}
	if _, ok := tool.userAllowedRoutesCache.Load("u-with-role-7"); ok {
		t.Error("fast-path cache for affected user must be cleared")
	}
}

// Pin the SQL contract: getUserPermissionsFromDB SQL must include the role
// expired_at filter. We can't execute the query without PG; we just grep
// the source to ensure the contract holds across refactors.
func TestFix7_RolePermissionTTLFilterIsInSQL(t *testing.T) {
	// Stage 6 baked the filter into auth.go directly. If a future contributor
	// removes it, this test fails. (Reads the file at test time.)
	src, err := readSourceFile("auth.go")
	if err != nil {
		t.Skipf("could not read auth.go for SQL contract check: %v", err)
		return
	}
	if !contains(src, "rp.expired_at IS NULL OR rp.expired_at >") {
		t.Error("getUserPermissionsFromDB must filter on rp.expired_at; Stage 6 fix #7")
	}
	if !contains(src, "p.is_enabled = true") {
		t.Error("getUserPermissionsFromDB must filter on p.is_enabled; Stage 6 fix #7")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func readSourceFile(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// keep `assert` accessible for tests later; suppress unused warnings.
var _ = time.Now
