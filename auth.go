package authing

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"authing/models"

	"github.com/gofiber/fiber/v2"
	"github.com/kmlixh/gom/v4"
	"github.com/kmlixh/gom/v4/define"
	"github.com/redis/go-redis/v9"
)

// AuthTool 认证工具结构体
type AuthTool struct {
	redisClient *redis.Client
	db          *gom.DB
	// 内存缓存
	userPermissionsCache sync.Map // 用户权限缓存
	rolePermissionsCache sync.Map // 角色权限缓存
	userRolesCache       sync.Map // 用户角色缓存
	// 缓存时间设置
	permissionCacheDuration time.Duration
}

// Config 配置结构体
type Config struct {
	RedisAddr               string
	RedisPassword           string
	RedisDB                 int
	DBDriver                string
	DBDSN                   string
	DBOptions               *define.DBOptions
	PermissionCacheDuration time.Duration // 权限缓存时间，默认为4小时
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
	}, nil
}

// ValidateToken 验证用户token
func (s *AuthTool) ValidateToken(ctx context.Context, token string) (string, error) {
	// 从Redis获取用户信息
	key := fmt.Sprintf("user_id_%s", token)
	userId, err := s.redisClient.Get(ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("invalid token: %v", err)
	}

	return userId, nil
}

// CheckPermission 检查用户是否有权限访问指定路由
func (s *AuthTool) CheckPermission(ctx context.Context, userID string, route string) (bool, error) {
	// 1. 检查路由是否在白名单中
	whitelisted, err := s.checkRouteWhitelist(route)
	if err != nil {
		return false, err
	}
	if whitelisted {
		return true, nil
	}

	// 2. 从内存缓存中获取用户权限
	if permissions, ok := s.userPermissionsCache.Load(userID); ok {
		permissionList := permissions.([]models.Permission)
		return s.matchRoute(permissionList, route), nil
	}

	// 3. 从Redis缓存中获取用户权限
	redisKey := fmt.Sprintf("user_permissions_%s", userID)
	if permissions, err := s.redisClient.Get(ctx, redisKey).Result(); err == nil {
		var permissionList []models.Permission
		if err := json.Unmarshal([]byte(permissions), &permissionList); err == nil {
			s.userPermissionsCache.Store(userID, permissionList)
			return s.matchRoute(permissionList, route), nil
		}
	}

	// 4. 从数据库获取用户权限并缓存
	if err := s.CacheUserPermissions(ctx, userID); err != nil {
		return false, err
	}

	// 从缓存中获取权限（此时缓存已更新）
	if permissions, ok := s.userPermissionsCache.Load(userID); ok {
		permissionList := permissions.([]models.Permission)
		return s.matchRoute(permissionList, route), nil
	}

	return false, fmt.Errorf("failed to get user permissions")
}

// CacheUserPermissions 缓存用户权限信息
func (s *AuthTool) CacheUserPermissions(ctx context.Context, userId string) error {
	permissions, err := s.getUserPermissionsFromDB(ctx, userId)
	if err != nil {
		return err
	}

	// 更新内存缓存
	s.userPermissionsCache.Store(userId, permissions)

	// 更新Redis缓存
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	return s.redisClient.Set(ctx, fmt.Sprintf("user_permissions_%s", userId), permissionsJSON, s.permissionCacheDuration).Err()
}

// AuthMiddleware 创建认证中间件
func (s *AuthTool) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 检查路由是否在白名单中
		route := c.Path()
		whitelisted, err := s.checkRouteWhitelist(route)
		if err == nil && whitelisted {
			return c.Next()
		}

		// 获取token
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Authorization token required",
			})
		}

		// 验证token
		userId, err := s.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		// 检查权限
		hasPermission, err := s.CheckPermission(c.Context(), userId, route)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": "Failed to check permission",
			})
		}

		if !hasPermission {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error": "Access denied",
			})
		}

		return c.Next()
	}
}

// 内部辅助方法

// checkRouteWhitelist 检查路由是否在白名单中
func (s *AuthTool) checkRouteWhitelist(route string) (bool, error) {
	var whitelist models.RouteWhitelist
	result := s.db.Chain().From(&whitelist).Where("route", define.OpEq, route).First(&whitelist)
	if result.Error != nil {
		return false, nil // 路由不在白名单中
	}
	return whitelist.IsAllowed, nil
}

// matchRoute 匹配路由和权限规则
func (s *AuthTool) matchRoute(permissions []models.Permission, route string) bool {
	for _, permission := range permissions {
		if !permission.IsEnabled {
			continue
		}
		matched, err := regexp.MatchString(permission.Route, route)
		if err == nil && matched {
			return true
		}
	}
	return false
}

// getUserPermissionsFromDB 从数据库获取用户权限
func (s *AuthTool) getUserPermissionsFromDB(ctx context.Context, userId string) ([]models.Permission, error) {
	var permissions []models.Permission

	// 获取用户直接权限
	result := s.db.Chain().
		SetContext(ctx).
		Table("user_permissions up").
		Fields("p.*").
		Join("JOIN permissions p ON up.permission_id = p.id").
		Where("up.user_id", define.OpEq, userId).
		And("(up.expired_at IS NULL OR up.expired_at > ?)", define.OpGt, time.Now()).
		List(&permissions)
	if result.Error != nil {
		return nil, result.Error
	}

	// 获取用户角色权限
	var rolePermissions []models.Permission
	result = s.db.Chain().
		SetContext(ctx).
		Table("user_roles ur").
		Fields("DISTINCT p.*").
		Join("JOIN role_permissions rp ON ur.role_id = rp.role_id").
		Join("JOIN permissions p ON rp.permission_id = p.id").
		Where("ur.user_id", define.OpEq, userId).
		List(&rolePermissions)
	if result.Error != nil {
		return nil, result.Error
	}

	// 合并权限列表
	permissions = append(permissions, rolePermissions...)
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
func (s *AuthTool) AssignRoleToUser(ctx context.Context, userId string, roleID int64) error {
	// 获取角色信息，确保角色存在
	_, err := s.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	// 创建用户角色关联
	userRole := &models.UserRole{
		UserID:    userId,
		RoleID:    roleID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result := s.db.Chain().From(userRole).Insert(userRole)
	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	s.userRolesCache.Delete(userId)
	s.userPermissionsCache.Delete(userId)

	return nil
}

// RemoveRoleFromUser 从用户中移除角色
func (s *AuthTool) RemoveRoleFromUser(userID string, roleID int64) error {
	result := s.db.Chain().From(&models.UserRole{}).
		Where("user_id", define.OpEq, userID).
		And("role_id", define.OpEq, roleID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	s.userRolesCache.Delete(userID)
	s.userPermissionsCache.Delete(userID)

	return nil
}

// GetUserRoles 获取用户的所有角色
func (s *AuthTool) GetUserRoles(ctx context.Context, userId string) ([]models.Role, error) {
	// 先从缓存获取
	if roles, ok := s.userRolesCache.Load(userId); ok {
		return roles.([]models.Role), nil
	}

	// 从数据库获取
	var roles []models.Role
	result := s.db.Chain().
		Table("user_roles ur").
		Fields("r.*").
		Join("JOIN roles r ON ur.role_id = r.id").
		Where("ur.user_id", define.OpEq, userId).
		List(&roles)

	if result.Error != nil {
		return nil, result.Error
	}

	// 更新缓存
	s.userRolesCache.Store(userId, roles)
	rolesJSON, _ := json.Marshal(roles)
	s.redisClient.Set(ctx, fmt.Sprintf("user_roles_%s", userId), rolesJSON, s.permissionCacheDuration)

	return roles, nil
}

// 以下是用户权限表的增删改查方法

// AssignPermissionToUser 为用户分配直接权限
func (s *AuthTool) AssignPermissionToUser(ctx context.Context, userId string, permissionID int64, expiredAt *time.Time) error {
	// 获取权限信息，确保权限存在
	_, err := s.GetPermissionByID(permissionID)
	if err != nil {
		return err
	}

	// 创建用户权限关联
	userPermission := &models.UserPermission{
		UserID:       userId,
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
	s.userPermissionsCache.Delete(userId)

	return nil
}

// RemovePermissionFromUser 从用户中移除直接权限
func (s *AuthTool) RemovePermissionFromUser(ctx context.Context, userId string, permissionID int64) error {
	result := s.db.Chain().From(&models.UserPermission{}).
		Where("user_id", define.OpEq, userId).
		And("permission_id", define.OpEq, permissionID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	s.userPermissionsCache.Delete(userId)

	return nil
}

// GetUserDirectPermissions 获取用户的直接权限
func (s *AuthTool) GetUserDirectPermissions(ctx context.Context, userId string) ([]models.Permission, error) {
	var permissions []models.Permission
	result := s.db.Chain().
		Table("user_permissions up").
		Fields("p.*").
		Join("JOIN permissions p ON up.permission_id = p.id").
		Where("up.user_id", define.OpEq, userId).
		And("(up.expired_at IS NULL OR up.expired_at > ?)", define.OpGt, time.Now()).
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
func (s *AuthTool) SetToken(ctx context.Context, token string, userId string, userInfo any, timeSpan int64) error {
	// 1. 存储用户ID
	userIdKey := fmt.Sprintf("user_id_%s", token)
	if err := s.redisClient.Set(ctx, userIdKey, userId, time.Duration(timeSpan)*time.Minute).Err(); err != nil {
		return fmt.Errorf("failed to set user id: %v", err)
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
	userID, err := strconv.ParseInt(userId, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid user id: %v", err)
	}

	// 缓存用户权限
	if err := s.CacheUserPermissions(ctx, userId); err != nil {
		return fmt.Errorf("failed to cache user permissions: %v", err)
	}

	// 获取并缓存用户角色
	roles, err := s.GetUserRoles(ctx, userId)
	if err != nil {
		return fmt.Errorf("failed to get user roles: %v", err)
	}
	s.userRolesCache.Store(userID, roles)
	rolesJSON, _ := json.Marshal(roles)
	if err := s.redisClient.Set(ctx, fmt.Sprintf("user_roles_%d", userID), rolesJSON, s.permissionCacheDuration).Err(); err != nil {
		return fmt.Errorf("failed to cache user roles: %v", err)
	}

	return nil
}
