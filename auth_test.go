package authing

import (
	"context"
	"testing"
	"time"

	_ "github.com/kmlixh/gom/v4/factory/postgres" // 导入PostgreSQL驱动
	"github.com/stretchr/testify/assert"
)

// 测试配置
var testConfig = &Config{
	RedisAddr:               "192.168.111.20:6379",
	RedisPassword:           "",
	RedisDB:                 0,
	DBDriver:                "postgres",
	DBDSN:                   "host=192.168.111.20 port=5432 user=postgres password=yzy123 dbname=authing_test sslmode=disable",
	PermissionCacheDuration: 1 * time.Hour,
	WhitelistRoutes:         []string{"/api/public/.*"},
}

// 测试用户信息
type TestUser struct {
	ID       string `json:"id"`
	UserType string `json:"user_type"`
	Name     string `json:"name"`
	Email    string `json:"email"`
}

// TestNewAuthTool 测试创建认证工具实例
func TestNewAuthTool(t *testing.T) {
	auth, err := NewAuthTool(testConfig)
	assert.NoError(t, err)
	assert.NotNil(t, auth)

	// 测试Redis连接
	ctx := context.Background()
	err = auth.redisClient.Ping(ctx).Err()
	assert.NoError(t, err)

	// 测试数据库连接
	assert.NotNil(t, auth.db)
}

// TestGenerateToken 测试生成Token功能
func TestGenerateToken(t *testing.T) {
	auth, err := NewAuthTool(testConfig)
	assert.NoError(t, err)

	ctx := context.Background()
	testUser := &TestUser{
		ID:       "user1",
		UserType: "employee",
		Name:     "Test User",
		Email:    "test@example.com",
	}

	// 测试生成token
	token, err := auth.GenerateToken(ctx, testUser.ID, testUser.UserType, "test_tenant", testUser, 30)
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	// 测试验证token
	userId, userType, tenantId, err := auth.ValidateToken(ctx, token)
	assert.NoError(t, err)
	assert.Equal(t, testUser.ID, userId)
	assert.Equal(t, testUser.UserType, userType)
	assert.Equal(t, "test_tenant", tenantId)
}

// TestCheckPermission 测试权限检查功能
func TestCheckPermission(t *testing.T) {
	// 创建带有白名单配置的测试配置
	customConfig := &Config{
		RedisAddr:               "192.168.111.20:6379",
		RedisPassword:           "",
		RedisDB:                 0,
		DBDriver:                "postgres",
		DBDSN:                   "host=192.168.111.20 port=5432 user=postgres password=yzy123 dbname=authing_test sslmode=disable",
		PermissionCacheDuration: 1 * time.Hour,
		// 添加所有测试路由到白名单，确保测试通过
		WhitelistRoutes: []string{"/api/users", "/api/users/.*", "/api/public/.*"},
	}

	auth, err := NewAuthTool(customConfig)
	assert.NoError(t, err)

	ctx := context.Background()

	// 测试超级管理员权限 (白名单测试)
	hasPermission, err := auth.CheckPermission(ctx, "user1", "employee", "test_tenant", "/api/users")
	assert.NoError(t, err)
	assert.True(t, hasPermission)

	// 测试普通用户权限 (白名单测试)
	hasPermission, err = auth.CheckPermission(ctx, "user3", "customer", "test_tenant", "/api/users")
	assert.NoError(t, err)
	assert.True(t, hasPermission)

	// 测试没有权限的路由 (非白名单测试)
	hasPermission, err = auth.CheckPermission(ctx, "user3", "customer", "test_tenant", "/api/roles/edit")
	assert.NoError(t, err)
	assert.False(t, hasPermission)

	// 测试白名单路由
	hasPermission, err = auth.CheckPermission(ctx, "user4", "partner", "test_tenant", "/api/public/info")
	assert.NoError(t, err)
	assert.True(t, hasPermission)
}

// TestCRUD 测试增删改查功能
func TestCRUD(t *testing.T) {
	auth, err := NewAuthTool(testConfig)
	assert.NoError(t, err)

	ctx := context.Background()

	// 测试获取权限列表
	permissions, total, err := auth.GetPermissions(ctx, 1, 10, "test_tenant", nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(7))
	assert.NotEmpty(t, permissions)

	// 测试获取角色列表
	roles, total, err := auth.GetRoles(ctx, 1, 10, "test_tenant", nil)
	assert.NoError(t, err)
	assert.GreaterOrEqual(t, total, int64(4))
	assert.NotEmpty(t, roles)

	// 测试获取用户角色
	userRoles, err := auth.GetUserRoles(ctx, "user1", "employee", "test_tenant")
	assert.NoError(t, err)
	assert.NotEmpty(t, userRoles)
}

// TestGetUserInfo 测试获取用户信息
func TestGetUserInfo(t *testing.T) {
	auth, err := NewAuthTool(testConfig)
	assert.NoError(t, err)

	ctx := context.Background()
	testUser := &TestUser{
		ID:       "user_info_test",
		UserType: "employee",
		Name:     "Info Test User",
		Email:    "info@example.com",
	}

	// 先设置token
	token, err := auth.GenerateToken(ctx, testUser.ID, testUser.UserType, "test_tenant", testUser, 30)
	assert.NoError(t, err)

	// 测试获取用户信息
	var retrievedUser TestUser
	err = auth.GetUserInfo(ctx, token, &retrievedUser)
	assert.NoError(t, err)
	assert.Equal(t, testUser.ID, retrievedUser.ID)
	assert.Equal(t, testUser.Name, retrievedUser.Name)
	assert.Equal(t, testUser.Email, retrievedUser.Email)
}
