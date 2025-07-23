package authing

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kmlixh/authing/models"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kmlixh/gom/v4"
	"github.com/kmlixh/gom/v4/define"
	_ "github.com/kmlixh/gom/v4/factory/postgres" // PostgreSQL驱动
	"github.com/redis/go-redis/v9"
)

// AuthTool 认证工具结构体
type AuthTool struct {
	redisClient             *redis.Client
	db                      *gom.DB
	permissionCacheDuration time.Duration
	config                  *Config
	mu                      sync.RWMutex
}

// MiddlewareOptions 定义了认证中间件的配置选项
type MiddlewareOptions struct {
	// SkipRoutes 是一个路由前缀列表，匹配这些前缀的路由将绕过认证
	SkipRoutes []string
}

// NewAuthTool 创建新的认证工具实例
func NewAuthTool(config *Config) (*AuthTool, error) {
	// 初始化Redis客户端
	redisClient := redis.NewClient(&redis.Options{
		Addr:     config.RedisAddr,
		Password: config.RedisPassword,
		DB:       config.RedisDB,
	})

	// 测试Redis连接
	ctx := context.Background()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis connection failed: %v", err)
	}

	// 初始化数据库连接
	db, err := gom.Open(config.DBDriver, config.DBDSN, config.DBOptions)
	if err != nil {
		return nil, fmt.Errorf("database connection failed: %v", err)
	}

	// 设置默认权限缓存时间
	permissionCacheDuration := config.PermissionCacheDuration
	if permissionCacheDuration == 0 {
		permissionCacheDuration = 4 * time.Hour
	}

	return &AuthTool{
		redisClient:             redisClient,
		db:                      db,
		permissionCacheDuration: permissionCacheDuration,
		config:                  config,
	}, nil
}

// ValidateToken 验证用户token
func (s *AuthTool) ValidateToken(ctx context.Context, token string) (string, string, string, error) {
	tokenKey := fmt.Sprintf("token:%s", token)
	data, err := s.redisClient.HMGet(ctx, tokenKey, "user_id", "user_type", "tenant_id").Result()
	if err != nil {
		return "", "", "", fmt.Errorf("failed to get token info from redis: %v", err)
	}
	if len(data) < 3 || data[0] == nil || data[1] == nil || data[2] == nil {
		return "", "", "", fmt.Errorf("invalid or expired token")
	}

	userId := data[0].(string)
	userType := data[1].(string)
	tenantId := data[2].(string)

	return userId, userType, tenantId, nil
}

// CheckPermission 检查用户是否有权限访问指定路由
func (s *AuthTool) CheckPermission(ctx context.Context, userID string, userType string, tenantID string, route string) (bool, error) {
	// 1. 检查路由是否在白名单中
	whitelisted, err := s.checkRouteWhitelist(route)
	if err != nil {
		return false, err
	}
	if whitelisted {
		return true, nil
	}

	// 2. 从Redis缓存中获取用户权限
	redisKey := fmt.Sprintf("user_permissions:%s:%s:%s", tenantID, userType, userID)
	cachedPermissions, err := s.redisClient.Get(ctx, redisKey).Result()
	if err == nil {
		var permissionList []models.Permission
		if err := json.Unmarshal([]byte(cachedPermissions), &permissionList); err == nil {
			return s.matchRoute(permissionList, route), nil
		}
	}

	// 3. 从数据库获取用户权限并缓存
	permissions, err := s.getUserPermissionsFromDB(ctx, userID, userType, tenantID)
	if err != nil {
		return false, fmt.Errorf("failed to get user permissions from db: %v", err)
	}

	// 缓存到Redis
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return false, fmt.Errorf("failed to marshal permissions: %v", err)
	}
	err = s.redisClient.Set(ctx, redisKey, permissionsJSON, s.permissionCacheDuration).Err()
	if err != nil {
		// 即使缓存失败，也应该继续完成本次权限检查
		fmt.Printf("Warning: failed to cache user permissions for user %s: %v", userID, err)
	}

	return s.matchRoute(permissions, route), nil
}

// CacheUserPermissions 缓存用户权限信息
func (s *AuthTool) CacheUserPermissions(ctx context.Context, userId string, userType string, tenantID string) error {
	permissions, err := s.getUserPermissionsFromDB(ctx, userId, userType, tenantID)
	if err != nil {
		return err
	}

	// 更新Redis缓存
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	redisKey := fmt.Sprintf("user_permissions:%s:%s:%s", tenantID, userType, userId)
	return s.redisClient.Set(ctx, redisKey, permissionsJSON, s.permissionCacheDuration).Err()
}

// NewAuthMiddleware 创建一个新的、可配置的认证中间件
func (s *AuthTool) NewAuthMiddleware(opts *MiddlewareOptions) fiber.Handler {
	return func(c *fiber.Ctx) error {
		route := c.Path()

		// 检查应用层传入的跳过路由列表
		if opts != nil {
			for _, skipRoute := range opts.SkipRoutes {
				if strings.HasPrefix(route, skipRoute) {
					return c.Next()
				}
			}
		}

		// 检查库配置的全局白名单
		whitelisted, err := s.checkRouteWhitelist(route)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error checking route whitelist",
			})
		}
		if whitelisted {
			return c.Next()
		}

		// 获取token
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Missing authorization token",
			})
		}

		// 验证token
		userId, userType, tenantId, err := s.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Invalid token",
			})
		}

		// 检查权限
		hasPermission, err := s.CheckPermission(c.Context(), userId, userType, tenantId, route)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error checking permissions",
			})
		}
		if !hasPermission {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"message": "Permission denied",
			})
		}

		// 将用户信息存储到上下文中
		c.Locals("user_id", userId)
		c.Locals("user_type", userType)
		c.Locals("tenant_id", tenantId)

		return c.Next()
	}
}

// AuthMiddleware 提供一个默认的认证中间件，用于向后兼容
func (s *AuthTool) AuthMiddleware() fiber.Handler {
	// 调用新的中间件构造函数，不带任何跳过选项
	return s.NewAuthMiddleware(nil)
}

// 内部辅助方法

// checkRouteWhitelist 检查路由是否在白名单中
func (s *AuthTool) checkRouteWhitelist(route string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// 检查黑名单
	for _, blackRoute := range s.config.BlacklistRoutes {
		if matched, _ := regexp.MatchString(blackRoute, route); matched {
			return false, nil
		}
	}

	// 检查白名单
	for _, whiteRoute := range s.config.WhitelistRoutes {
		if matched, _ := regexp.MatchString(whiteRoute, route); matched {
			return true, nil
		}
	}

	return false, nil
}

// matchRoute 匹配路由和权限规则
func (s *AuthTool) matchRoute(permissions []models.Permission, route string) bool {
	for _, permission := range permissions {
		if !permission.IsEnabled {
			continue
		}

		// 首先尝试直接匹配
		if permission.Route == route {
			return true
		}

		// 然后尝试正则匹配
		matched, err := regexp.MatchString(permission.Route, route)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// getUserPermissionsFromDB 从数据库获取用户权限
func (s *AuthTool) getUserPermissionsFromDB(ctx context.Context, userId string, userType string, tenantID string) ([]models.Permission, error) {
	var permissions []models.Permission
	now := time.Now()

	// 使用原始SQL查询获取用户的权限，PostgreSQL使用$1,$2等形式的参数占位符
	sql := `
		SELECT p.* FROM permissions p
		JOIN user_permissions up ON p.id = up.permission_id
		WHERE up.user_id = $1 AND up.user_type = $2 AND up.tenant_id = $3 AND p.tenant_id = $4
		AND (up.expired_at IS NULL OR up.expired_at > $5)
		
		UNION
		
		SELECT p.* FROM permissions p
		JOIN role_permissions rp ON p.id = rp.permission_id
		JOIN user_roles ur ON rp.role_id = ur.role_id
		WHERE ur.user_id = $6 AND ur.user_type = $7 AND ur.tenant_id = $8
		AND rp.tenant_id = $9 AND p.tenant_id = $10
	`

	args := []interface{}{
		userId, userType, tenantID, tenantID, now,
		userId, userType, tenantID, tenantID, tenantID,
	}

	result := s.db.Chain().RawQuery(sql, args...)
	if result.Error != nil {
		return nil, result.Error
	}

	err := result.Into(&permissions)
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// clearUserPermissionsCache 清除单个用户的权限缓存
func (s *AuthTool) clearUserPermissionsCache(ctx context.Context, tenantID, userID, userType string) error {
	redisKey := fmt.Sprintf("user_permissions:%s:%s:%s", tenantID, userID, userType)
	return s.redisClient.Del(ctx, redisKey).Err()
}

// clearUsersPermissionsCacheByRole 清除拥有特定角色的所有用户的权限缓存
func (s *AuthTool) clearUsersPermissionsCacheByRole(ctx context.Context, roleID int64) error {
	var userRoles []models.UserRole
	result := s.db.Chain().From(&models.UserRole{}).Where("role_id", define.OpEq, roleID).List(&userRoles)
	if result.Error != nil {
		return result.Error
	}

	if len(userRoles) == 0 {
		return nil
	}

	// 使用pipeline批量删除
	pipe := s.redisClient.Pipeline()
	for _, ur := range userRoles {
		redisKey := fmt.Sprintf("user_permissions:%s:%s:%s", ur.TenantID, ur.UserID, ur.UserType)
		pipe.Del(ctx, redisKey)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// clearUsersPermissionsCacheByPermission 清除拥有特定直接权限的所有用户的权限缓存
func (s *AuthTool) clearUsersPermissionsCacheByPermission(ctx context.Context, permissionID int64) error {
	// 1. 清除直接拥有该权限的用户缓存
	var userPermissions []models.UserPermission
	result := s.db.Chain().From(&models.UserPermission{}).Where("permission_id", define.OpEq, permissionID).List(&userPermissions)
	if result.Error != nil {
		return result.Error
	}

	pipe := s.redisClient.Pipeline()
	for _, up := range userPermissions {
		redisKey := fmt.Sprintf("user_permissions:%s:%s:%s", up.TenantID, up.UserID, up.UserType)
		pipe.Del(ctx, redisKey)
	}

	// 2. 清除通过角色拥有该权限的用户缓存
	var rolePermissions []models.RolePermission
	result = s.db.Chain().From(&models.RolePermission{}).Where("permission_id", define.OpEq, permissionID).List(&rolePermissions)
	if result.Error != nil {
		return result.Error
	}

	for _, rp := range rolePermissions {
		var userRoles []models.UserRole
		result := s.db.Chain().From(&models.UserRole{}).Where("role_id", define.OpEq, rp.RoleID).List(&userRoles)
		if result.Error != nil {
			// 记录错误但继续
			fmt.Printf("Warning: failed to get users for role %d: %v", rp.RoleID, result.Error)
			continue
		}
		for _, ur := range userRoles {
			redisKey := fmt.Sprintf("user_permissions:%s:%s:%s", ur.TenantID, ur.UserID, ur.UserType)
			pipe.Del(ctx, redisKey)
		}
	}

	_, err := pipe.Exec(ctx)
	return err
}

// 以下是权限表的增删改查方法

// CreatePermission 创建权限
func (s *AuthTool) CreatePermission(ctx context.Context, permission *models.Permission) error {
	result := s.db.Chain().From(permission).Insert(permission)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetPermissionByID 根据ID获取权限
func (s *AuthTool) GetPermissionByID(ctx context.Context, id int64) (*models.Permission, error) {
	var permission models.Permission
	result := s.db.Chain().From(&permission).Where("id", define.OpEq, id).First(&permission)
	if result.Error != nil {
		return nil, result.Error
	}
	return &permission, nil
}

// UpdatePermission 更新权限
func (s *AuthTool) UpdatePermission(ctx context.Context, permission *models.Permission) error {
	result := s.db.Chain().From(permission).Where("id", define.OpEq, permission.ID).Update(permission)
	if result.Error != nil {
		return result.Error
	}
	// 清除与此权限相关的用户缓存
	return s.clearUsersPermissionsCacheByPermission(ctx, permission.ID)
}

// DeletePermission 删除权限
func (s *AuthTool) DeletePermission(ctx context.Context, id int64) error {
	// 先清除缓存，再删除数据
	err := s.clearUsersPermissionsCacheByPermission(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to clear user permissions cache before deleting permission: %v", err)
	}
	result := s.db.Chain().From(&models.Permission{}).Where("id", define.OpEq, id).Delete()
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ListPermissions 获取权限列表
func (s *AuthTool) ListPermissions(page, pageSize int) ([]models.Permission, int64, error) {
	var permissions []models.Permission
	chain := s.db.Chain().From(&models.Permission{})

	// 获取总数
	total, err := chain.Count()
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	result := chain.Page(page, pageSize).List(&permissions)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return permissions, total, nil
}

// 以下是角色表的增删改查方法

// CreateRole 创建角色
func (s *AuthTool) CreateRole(ctx context.Context, role *models.Role) error {
	result := s.db.Chain().From(role).Insert(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetRoleByID 根据ID获取角色
func (s *AuthTool) GetRoleByID(ctx context.Context, id int64) (*models.Role, error) {
	var role models.Role
	result := s.db.Chain().From(&role).Where("id", define.OpEq, id).First(&role)
	if result.Error != nil {
		return nil, result.Error
	}
	return &role, nil
}

// UpdateRole 更新角色
func (s *AuthTool) UpdateRole(ctx context.Context, role *models.Role) error {
	result := s.db.Chain().From(role).Where("id", define.OpEq, role.ID).Update(role)
	if result.Error != nil {
		return result.Error
	}
	// 如果角色名等信息更新，可能需要更新关联信息，但更重要的是清除拥有此角色的用户权限缓存
	return s.clearUsersPermissionsCacheByRole(ctx, role.ID)
}

// DeleteRole 删除角色
func (s *AuthTool) DeleteRole(ctx context.Context, id int64) error {
	// 先清除缓存
	err := s.clearUsersPermissionsCacheByRole(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to clear user permissions cache before deleting role: %v", err)
	}
	result := s.db.Chain().From(&models.Role{}).Where("id", define.OpEq, id).Delete()
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ListRoles 获取角色列表
func (s *AuthTool) ListRoles(page, pageSize int) ([]models.Role, int64, error) {
	var roles []models.Role
	chain := s.db.Chain().From(&models.Role{})

	// 获取总数
	total, err := chain.Count()
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	result := chain.Page(page, pageSize).List(&roles)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return roles, total, nil
}

// 以下是角色权限关联表的增删改查方法

// AssignPermissionToRole 为角色分配权限
func (s *AuthTool) AssignPermissionToRole(ctx context.Context, roleID, permissionID int64) error {
	// 获取角色和权限信息
	role, err := s.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	permission, err := s.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}

	// 创建角色权限关联
	rolePermission := &models.RolePermission{
		RoleID:         roleID,
		PermissionID:   permissionID,
		RoleName:       role.Name,
		PermissionName: permission.Name,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	result := s.db.Chain().From(rolePermission).Insert(rolePermission)
	if result.Error != nil {
		return result.Error
	}

	// 清除拥有该角色的所有用户的权限缓存
	return s.clearUsersPermissionsCacheByRole(ctx, roleID)
}

// RemovePermissionFromRole 从角色中移除权限
func (s *AuthTool) RemovePermissionFromRole(ctx context.Context, roleID, permissionID int64) error {
	result := s.db.Chain().From(&models.RolePermission{}).
		Where("role_id", define.OpEq, roleID).
		And("permission_id", define.OpEq, permissionID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除拥有该角色的所有用户的权限缓存
	return s.clearUsersPermissionsCacheByRole(ctx, roleID)
}

// GetRolePermissions 获取角色的所有权限
func (s *AuthTool) GetRolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error) {
	// 此函数现在不直接被权限检查逻辑使用，可以不使用缓存或使用独立的Redis缓存
	var permissions []models.Permission
	result := s.db.Chain().
		Table("role_permissions rp").
		Fields("p.*").
		Join("JOIN permissions p ON rp.permission_id = p.id").
		Where("rp.role_id", define.OpEq, roleID).
		List(&permissions)

	if result.Error != nil {
		return nil, result.Error
	}

	return permissions, nil
}

// 以下是用户角色关联表的增删改查方法

// AssignRoleToUser 为用户分配角色
func (s *AuthTool) AssignRoleToUser(ctx context.Context, tenantID, userId string, userType string, roleID int64) error {
	// 获取角色信息，确保角色存在
	_, err := s.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 创建用户角色关联
	userRole := &models.UserRole{
		TenantID:  tenantID,
		UserID:    userId,
		UserType:  userType,
		RoleID:    roleID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result := s.db.Chain().From(userRole).Insert(userRole)
	if result.Error != nil {
		return result.Error
	}

	// 清除该用户的权限缓存
	return s.clearUserPermissionsCache(ctx, tenantID, userId, userType)
}

// RemoveRoleFromUser 从用户中移除角色
func (s *AuthTool) RemoveRoleFromUser(ctx context.Context, tenantID, userID string, userType string, roleID int64) error {
	result := s.db.Chain().From(&models.UserRole{}).
		Where("user_id", define.OpEq, userID).
		And("user_type", define.OpEq, userType).
		And("role_id", define.OpEq, roleID).
		And("tenant_id", define.OpEq, tenantID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除该用户的权限缓存
	return s.clearUserPermissionsCache(ctx, tenantID, userID, userType)
}

// GetUserRoles 获取用户的所有角色
func (s *AuthTool) GetUserRoles(ctx context.Context, userId string, userType string, tenantID string) ([]models.Role, error) {
	// 此函数不直接被权限检查逻辑使用，可以不使用缓存或使用独立的Redis缓存
	sql := `
		SELECT r.* FROM roles r
		JOIN user_roles ur ON r.id = ur.role_id
		WHERE ur.user_id = $1 AND ur.user_type = $2 AND ur.tenant_id = $3 AND r.tenant_id = $4
	`

	args := []interface{}{userId, userType, tenantID, tenantID}

	var roles []models.Role
	result := s.db.Chain().RawQuery(sql, args...)

	if result.Error != nil {
		return nil, result.Error
	}

	err := result.Into(&roles)
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// 以下是用户权限表的增删改查方法

// AssignPermissionToUser 为用户分配直接权限
func (s *AuthTool) AssignPermissionToUser(ctx context.Context, tenantID, userId string, userType string, permissionID int64, expiredAt *time.Time) error {
	// 获取权限信息，确保权限存在
	_, err := s.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}

	// 创建用户权限关联
	userPermission := &models.UserPermission{
		TenantID:     tenantID,
		UserID:       userId,
		UserType:     userType,
		PermissionID: permissionID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// 如果提供了过期时间，则设置
	if expiredAt != nil {
		userPermission.ExpiredAt = *expiredAt
	}

	result := s.db.Chain().From(userPermission).Insert(userPermission)
	if result.Error != nil {
		return result.Error
	}

	// 清除该用户的权限缓存
	return s.clearUserPermissionsCache(ctx, tenantID, userId, userType)
}

// RemovePermissionFromUser 从用户中移除直接权限
func (s *AuthTool) RemovePermissionFromUser(ctx context.Context, tenantID, userId string, userType string, permissionID int64) error {
	result := s.db.Chain().From(&models.UserPermission{}).
		Where("user_id", define.OpEq, userId).
		And("user_type", define.OpEq, userType).
		And("permission_id", define.OpEq, permissionID).
		And("tenant_id", define.OpEq, tenantID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除该用户的权限缓存
	return s.clearUserPermissionsCache(ctx, tenantID, userId, userType)
}

// GetUserDirectPermissions 获取用户的直接权限
func (s *AuthTool) GetUserDirectPermissions(ctx context.Context, userId string, userType string) ([]models.Permission, error) {
	var permissions []models.Permission
	now := time.Now()

	result := s.db.Chain().
		Table("permissions").
		Join("user_permissions ON user_permissions.permission_id = permissions.id").
		Where("user_permissions.user_id", define.OpEq, userId).
		And("user_permissions.user_type", define.OpEq, userType).
		WhereRaw("user_permissions.expired_at IS NULL OR user_permissions.expired_at > ?", now).
		List(&permissions)

	if result.Error != nil {
		return nil, result.Error
	}

	return permissions, nil
}

// 以下是路由白名单表的增删改查方法

// AddRouteWhitelist 添加路由白名单
func (s *AuthTool) AddRouteWhitelist(ctx context.Context, route string, isAllowed bool, ipList string) error {
	whitelist := &models.RouteWhitelist{
		Route:     route,
		IsAllowed: isAllowed,
		IPList:    ipList,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result := s.db.Chain().From(whitelist).Insert(whitelist)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// UpdateRouteWhitelist 更新路由白名单
func (s *AuthTool) UpdateRouteWhitelist(ctx context.Context, id int64, isAllowed bool, ipList string) error {
	whitelist := &models.RouteWhitelist{
		ID:        id,
		IsAllowed: isAllowed,
		IPList:    ipList,
		UpdatedAt: time.Now(),
	}

	result := s.db.Chain().From(whitelist).Where("id", define.OpEq, id).Update(whitelist)
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// DeleteRouteWhitelist 删除路由白名单
func (s *AuthTool) DeleteRouteWhitelist(id int64) error {
	result := s.db.Chain().From(&models.RouteWhitelist{}).Where("id", define.OpEq, id).Delete()
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// ListRouteWhitelists 获取路由白名单列表
func (s *AuthTool) ListRouteWhitelists(page, pageSize int) ([]models.RouteWhitelist, int64, error) {
	var whitelists []models.RouteWhitelist
	chain := s.db.Chain().From(&models.RouteWhitelist{})

	// 获取总数
	total, err := chain.Count()
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	result := chain.Page(page, pageSize).List(&whitelists)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return whitelists, total, nil
}

// SetToken 设置用户token并缓存相关信息
func (s *AuthTool) SetToken(ctx context.Context, token string, userId string, userType string, tenantID string, userInfo any, timeSpan int64) error {
	// 1. 使用Redis Hash聚合存储Token信息
	tokenKey := fmt.Sprintf("token:%s", token)
	tokenData := map[string]interface{}{
		"user_id":   userId,
		"user_type": userType,
		"tenant_id": tenantID,
	}

	// 存储用户信息（如果提供）
	if userInfo != nil {
		userInfoJSON, err := json.Marshal(userInfo)
		if err != nil {
			return fmt.Errorf("failed to marshal user info: %v", err)
		}
		tokenData["user_info"] = userInfoJSON
	}

	if err := s.redisClient.HSet(ctx, tokenKey, tokenData).Err(); err != nil {
		return fmt.Errorf("failed to set token info in redis: %v", err)
	}

	// 设置过期时间
	expire := time.Duration(timeSpan) * time.Minute
	if err := s.redisClient.Expire(ctx, tokenKey, expire).Err(); err != nil {
		return fmt.Errorf("failed to set token expiration: %v", err)
	}

	// 2. 预热用户权限缓存
	if err := s.CacheUserPermissions(ctx, userId, userType, tenantID); err != nil {
		// 记录错误但允许登录继续
		fmt.Printf("Warning: failed to pre-cache user permissions for user %s: %v", userId, err)
	}

	return nil
}

// GenerateToken 生成UUID作为token并设置用户token缓存
func (s *AuthTool) GenerateToken(ctx context.Context, userId string, userType string, tenantID string, userInfo any, timeSpan int64) (string, error) {
	// 生成UUID作为token
	token := uuid.New().String()

	// 调用SetToken方法
	err := s.SetToken(ctx, token, userId, userType, tenantID, userInfo, timeSpan)
	if err != nil {
		return "", err
	}

	return token, nil
}

// GetUserInfo 从Redis缓存中获取用户信息
func (s *AuthTool) GetUserInfo(ctx context.Context, token string, userInfo any) error {
	tokenKey := fmt.Sprintf("token:%s", token)
	userInfoJSON, err := s.redisClient.HGet(ctx, tokenKey, "user_info").Result()
	if err != nil {
		return fmt.Errorf("failed to get user info from redis: %v", err)
	}

	if err := json.Unmarshal([]byte(userInfoJSON), userInfo); err != nil {
		return fmt.Errorf("failed to unmarshal user info: %v", err)
	}

	return nil
}

// GetPermissions 获取权限列表
func (s *AuthTool) GetPermissions(ctx context.Context, page int, pageSize int, tenantID string, filter map[string]interface{}) ([]models.Permission, int64, error) {
	var permissions []models.Permission

	// 构建查询条件
	chain := s.db.Chain().SetContext(ctx).Table("permissions").Where("tenant_id", define.OpEq, tenantID)

	// 添加过滤条件
	if filter != nil {
		for k, v := range filter {
			chain.And(k, define.OpEq, v)
		}
	}

	// 获取总数
	total, err := chain.Count()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count permissions: %v", err)
	}

	// 获取分页数据
	result := chain.Page(page, pageSize).List(&permissions)
	if result.Error != nil {
		return nil, 0, fmt.Errorf("failed to get permissions: %v", result.Error)
	}

	return permissions, total, nil
}

// GetRoles 获取角色列表
func (s *AuthTool) GetRoles(ctx context.Context, page int, pageSize int, tenantID string, filter map[string]interface{}) ([]models.Role, int64, error) {
	var roles []models.Role

	// 构建查询条件
	chain := s.db.Chain().SetContext(ctx).Table("roles").Where("tenant_id", define.OpEq, tenantID)

	// 添加过滤条件
	if filter != nil {
		for k, v := range filter {
			chain.And(k, define.OpEq, v)
		}
	}

	// 获取总数
	total, err := chain.Count()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %v", err)
	}

	// 获取分页数据
	result := chain.Page(page, pageSize).List(&roles)
	if result.Error != nil {
		return nil, 0, fmt.Errorf("failed to get roles: %v", result.Error)
	}

	return roles, total, nil
}

// CreateTenant 创建新租户
func (s *AuthTool) CreateTenant(ctx context.Context, tenantID, name, description string) error {
	tenant := models.NewTenant(tenantID, name, description)
	result := s.db.Chain().Insert(tenant)
	return result.Error
}

// GetTenant 获取租户信息
func (s *AuthTool) GetTenant(ctx context.Context, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant
	result := s.db.Chain().Table(tenant.TableName()).
		Where("tenant_id", define.OpEq, tenantID).
		First(&tenant)

	if result.Error != nil {
		return nil, result.Error
	}

	return &tenant, nil
}

// UpdateTenant 更新租户信息
func (s *AuthTool) UpdateTenant(ctx context.Context, tenant *models.Tenant) error {
	tenant.UpdatedAt = time.Now()
	result := s.db.Chain().Update(tenant)
	return result.Error
}

// DeleteTenant 删除租户
func (s *AuthTool) DeleteTenant(ctx context.Context, tenantID string) error {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}

	result := s.db.Chain().Delete(tenant)
	return result.Error
}

// GetTenants 获取租户列表
func (s *AuthTool) GetTenants(ctx context.Context, page, pageSize int, condition map[string]interface{}) ([]models.Tenant, int64, error) {
	var tenants []models.Tenant
	var tenant models.Tenant

	// 构建查询
	chain := s.db.Chain().Table(tenant.TableName())

	// 添加查询条件
	if condition != nil {
		for k, v := range condition {
			chain = chain.Where(k, define.OpEq, v)
		}
	}

	// 获取总数
	total, err := chain.Count()
	if err != nil {
		return nil, 0, err
	}

	// 分页查询
	result := chain.Offset((page - 1) * pageSize).Limit(pageSize).List(&tenants)
	if result.Error != nil {
		return nil, 0, result.Error
	}

	return tenants, total, nil
}
