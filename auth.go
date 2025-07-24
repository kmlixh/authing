package authing

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
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
	userRolesCache          sync.Map
	userPermissionsCache    sync.Map
	rolePermissionsCache    sync.Map
	permissionCacheDuration time.Duration
	config                  *Config
	mu                      sync.RWMutex
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
	// 从Redis获取用户ID、类型和租户ID
	userIdKey := fmt.Sprintf("user_id_%s", token)
	userId, err := s.redisClient.Get(ctx, userIdKey).Result()
	if err != nil {
		return "", "", "", fmt.Errorf("invalid token: %v", err)
	}

	userTypeKey := fmt.Sprintf("user_type_%s", token)
	userType, err := s.redisClient.Get(ctx, userTypeKey).Result()
	if err != nil {
		return "", "", "", fmt.Errorf("invalid token: %v", err)
	}

	tenantIdKey := fmt.Sprintf("tenant_id_%s", token)
	tenantId, err := s.redisClient.Get(ctx, tenantIdKey).Result()
	if err != nil {
		return "", "", "", fmt.Errorf("invalid token: %v", err)
	}

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

	// 2. 从内存缓存中获取用户权限
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userID)
	if permissions, ok := s.userPermissionsCache.Load(cacheKey); ok {
		permissionList := permissions.([]models.Permission)
		return s.matchRoute(permissionList, route), nil
	}

	// 3. 从Redis缓存中获取用户权限
	redisKey := fmt.Sprintf("user_permissions_%s_%s_%s", tenantID, userType, userID)
	if permissions, err := s.redisClient.Get(ctx, redisKey).Result(); err == nil {
		var permissionList []models.Permission
		if err := json.Unmarshal([]byte(permissions), &permissionList); err == nil {
			s.userPermissionsCache.Store(cacheKey, permissionList)
			return s.matchRoute(permissionList, route), nil
		}
	}

	// 4. 从数据库获取用户权限并缓存
	if err := s.CacheUserPermissions(ctx, userID, userType, tenantID); err != nil {
		return false, err
	}

	// 从缓存中获取权限（此时缓存已更新）
	if permissions, ok := s.userPermissionsCache.Load(cacheKey); ok {
		permissionList := permissions.([]models.Permission)
		return s.matchRoute(permissionList, route), nil
	}

	return false, fmt.Errorf("failed to get user permissions")
}

// CacheUserPermissions 缓存用户权限信息
func (s *AuthTool) CacheUserPermissions(ctx context.Context, userId string, userType string, tenantID string) error {
	permissions, err := s.getUserPermissionsFromDB(ctx, userId, userType, tenantID)
	if err != nil {
		return err
	}

	// 更新内存缓存
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userId)
	s.userPermissionsCache.Store(cacheKey, permissions)

	// 更新Redis缓存
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	redisKey := fmt.Sprintf("user_permissions_%s_%s_%s", tenantID, userType, userId)
	return s.redisClient.Set(ctx, redisKey, permissionsJSON, s.permissionCacheDuration).Err()
}

// AuthMiddleware 认证中间件
func (s *AuthTool) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 获取请求路径
		route := c.Path()

		// 检查路由白名单
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
		token := c.Get("Token")
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

	// 优化后的SQL查询，合并了tenant_id的判断，并简化了参数
	sql := `
		SELECT p.*
		FROM tb_permission p
		WHERE p.tenant_id = $1 AND (
			-- 直接用户权限
			EXISTS (
				SELECT 1
				FROM tb_user_permission up
				WHERE up.permission_id = p.id
				  AND up.user_id = $2
				  AND up.user_type = $3
				  AND up.tenant_id = $1
				  AND (up.expired_at IS NULL OR up.expired_at > $4)
			)
			-- 通过角色继承的权限
			OR EXISTS (
				SELECT 1
				FROM tb_role_permission rp
				JOIN tb_user_role ur ON rp.role_id = ur.role_id
				WHERE rp.permission_id = p.id
				  AND ur.user_id = $2
				  AND ur.user_type = $3
				  AND ur.tenant_id = $1
				  AND rp.tenant_id = $1
			)
		)
	`

	args := []interface{}{
		tenantID, userId, userType, now,
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

// 以下是权限表的增删改查方法

// CreatePermission 创建权限
func (s *AuthTool) CreatePermission(permission *models.Permission) error {
	result := s.db.Chain().From(permission).Insert(permission)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetPermissionByID 根据ID获取权限
func (s *AuthTool) GetPermissionByID(id int64) (*models.Permission, error) {
	var permission models.Permission
	result := s.db.Chain().From(&permission).Where("id", define.OpEq, id).First(&permission)
	if result.Error != nil {
		return nil, result.Error
	}
	return &permission, nil
}

// UpdatePermission 更新权限
func (s *AuthTool) UpdatePermission(permission *models.Permission) error {
	result := s.db.Chain().From(permission).Where("id", define.OpEq, permission.ID).Update(permission)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeletePermission 删除权限
func (s *AuthTool) DeletePermission(id int64) error {
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
func (s *AuthTool) CreateRole(role *models.Role) error {
	result := s.db.Chain().From(role).Insert(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetRoleByID 根据ID获取角色
func (s *AuthTool) GetRoleByID(id int64) (*models.Role, error) {
	var role models.Role
	result := s.db.Chain().From(&role).Where("id", define.OpEq, id).First(&role)
	if result.Error != nil {
		return nil, result.Error
	}
	return &role, nil
}

// UpdateRole 更新角色
func (s *AuthTool) UpdateRole(role *models.Role) error {
	result := s.db.Chain().From(role).Where("id", define.OpEq, role.ID).Update(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeleteRole 删除角色
func (s *AuthTool) DeleteRole(id int64) error {
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
func (s *AuthTool) AssignPermissionToRole(roleID, permissionID int64) error {
	// 获取角色和权限信息
	role, err := s.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	permission, err := s.GetPermissionByID(permissionID)
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

	// 清除缓存
	s.rolePermissionsCache.Delete(roleID)

	return nil
}

// RemovePermissionFromRole 从角色中移除权限
func (s *AuthTool) RemovePermissionFromRole(roleID, permissionID int64) error {
	result := s.db.Chain().From(&models.RolePermission{}).
		Where("role_id", define.OpEq, roleID).
		And("permission_id", define.OpEq, permissionID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	s.rolePermissionsCache.Delete(roleID)

	return nil
}

// GetRolePermissions 获取角色的所有权限 (需要保留 ctx 用于缓存更新)
func (s *AuthTool) GetRolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error) {
	// 先从缓存获取
	if permissions, ok := s.rolePermissionsCache.Load(roleID); ok {
		return permissions.([]models.Permission), nil
	}

	// 从数据库获取
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

	// 更新缓存
	s.rolePermissionsCache.Store(roleID, permissions)

	return permissions, nil
}

// 以下是用户角色关联表的增删改查方法

// AssignRoleToUser 为用户分配角色
func (s *AuthTool) AssignRoleToUser(ctx context.Context, userId string, userType string, roleID int64) error {
	// 获取角色信息，确保角色存在
	_, err := s.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	// 创建用户角色关联
	userRole := &models.UserRole{
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

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s", userType, userId)
	s.userRolesCache.Delete(cacheKey)
	s.userPermissionsCache.Delete(cacheKey)

	return nil
}

// RemoveRoleFromUser 从用户中移除角色
func (s *AuthTool) RemoveRoleFromUser(userID string, userType string, roleID int64) error {
	result := s.db.Chain().From(&models.UserRole{}).
		Where("user_id", define.OpEq, userID).
		And("user_type", define.OpEq, userType).
		And("role_id", define.OpEq, roleID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s", userType, userID)
	s.userRolesCache.Delete(cacheKey)
	s.userPermissionsCache.Delete(cacheKey)

	return nil
}

// GetUserRoles 获取用户的所有角色
func (s *AuthTool) GetUserRoles(ctx context.Context, userId string, userType string, tenantID string) ([]models.Role, error) {
	// 先从缓存获取
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userId)
	if roles, ok := s.userRolesCache.Load(cacheKey); ok {
		return roles.([]models.Role), nil
	}

	// 使用原始SQL查询获取用户角色
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

	// 更新缓存
	s.userRolesCache.Store(cacheKey, roles)
	rolesJSON, _ := json.Marshal(roles)
	redisKey := fmt.Sprintf("user_roles_%s_%s_%s", tenantID, userType, userId)
	if err := s.redisClient.Set(ctx, redisKey, rolesJSON, s.permissionCacheDuration).Err(); err != nil {
		return nil, err
	}

	return roles, nil
}

// 以下是用户权限表的增删改查方法

// AssignPermissionToUser 为用户分配直接权限
func (s *AuthTool) AssignPermissionToUser(ctx context.Context, userId string, userType string, permissionID int64, expiredAt *time.Time) error {
	// 获取权限信息，确保权限存在
	_, err := s.GetPermissionByID(permissionID)
	if err != nil {
		return err
	}

	// 创建用户权限关联
	userPermission := &models.UserPermission{
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

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s", userType, userId)
	s.userPermissionsCache.Delete(cacheKey)

	return nil
}

// RemovePermissionFromUser 从用户中移除直接权限
func (s *AuthTool) RemovePermissionFromUser(ctx context.Context, userId string, userType string, permissionID int64) error {
	result := s.db.Chain().From(&models.UserPermission{}).
		Where("user_id", define.OpEq, userId).
		And("user_type", define.OpEq, userType).
		And("permission_id", define.OpEq, permissionID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s", userType, userId)
	s.userPermissionsCache.Delete(cacheKey)

	return nil
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
	// 1. 存储用户ID、类型和租户ID
	userIdKey := fmt.Sprintf("user_id_%s", token)
	if err := s.redisClient.Set(ctx, userIdKey, userId, time.Duration(timeSpan)*time.Minute).Err(); err != nil {
		return fmt.Errorf("failed to set user id: %v", err)
	}

	userTypeKey := fmt.Sprintf("user_type_%s", token)
	if err := s.redisClient.Set(ctx, userTypeKey, userType, time.Duration(timeSpan)*time.Minute).Err(); err != nil {
		return fmt.Errorf("failed to set user type: %v", err)
	}

	tenantIDKey := fmt.Sprintf("tenant_id_%s", token)
	if err := s.redisClient.Set(ctx, tenantIDKey, tenantID, time.Duration(timeSpan)*time.Minute).Err(); err != nil {
		return fmt.Errorf("failed to set tenant id: %v", err)
	}

	// 2. 存储用户信息
	userInfoKey := fmt.Sprintf("user_info_%s", token)
	userInfoJSON, err := json.Marshal(userInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal user info: %v", err)
	}
	if err := s.redisClient.Set(ctx, userInfoKey, userInfoJSON, time.Duration(timeSpan)*time.Minute).Err(); err != nil {
		return fmt.Errorf("failed to set user info: %v", err)
	}

	// 3. 缓存用户权限信息
	// 缓存用户权限
	if err := s.CacheUserPermissions(ctx, userId, userType, tenantID); err != nil {
		return fmt.Errorf("failed to cache user permissions: %v", err)
	}

	// 获取并缓存用户角色
	roles, err := s.GetUserRoles(ctx, userId, userType, tenantID)
	if err != nil {
		return fmt.Errorf("failed to get user roles: %v", err)
	}

	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userId)
	s.userRolesCache.Store(cacheKey, roles)

	rolesJSON, _ := json.Marshal(roles)
	rolesCacheKey := fmt.Sprintf("user_roles_%s_%s_%s", tenantID, userType, userId)
	if err := s.redisClient.Set(ctx, rolesCacheKey, rolesJSON, s.permissionCacheDuration).Err(); err != nil {
		return fmt.Errorf("failed to cache user roles: %v", err)
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
	userInfoKey := fmt.Sprintf("user_info_%s", token)
	userInfoJSON, err := s.redisClient.Get(ctx, userInfoKey).Result()
	if err != nil {
		return fmt.Errorf("failed to get user info: %v", err)
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
