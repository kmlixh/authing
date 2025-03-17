package authing

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"authing/models"

	"github.com/gofiber/fiber/v2"
	"github.com/kmlixh/gom/v4"
	"github.com/kmlixh/gom/v4/define"
	"github.com/redis/go-redis/v9"
)

// AuthService 认证服务结构体
type AuthService struct {
	redisClient *redis.Client
	db          *gom.DB
	// 内存缓存
	userPermissionsCache sync.Map // 用户权限缓存
	rolePermissionsCache sync.Map // 角色权限缓存
	userRolesCache       sync.Map // 用户角色缓存
}

// Config 配置结构体
type Config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	DBDriver      string
	DBDSN         string
	DBOptions     *define.DBOptions
}

// NewAuthService 创建新的认证服务实例
func NewAuthService(config *Config) (*AuthService, error) {
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

	return &AuthService{
		redisClient: redisClient,
		db:          db,
	}, nil
}

// ValidateToken 验证用户token
func (s *AuthService) ValidateToken(ctx context.Context, token string) (*models.User, error) {
	// 从Redis获取用户信息
	key := fmt.Sprintf("user_token_%s", token)
	userData, err := s.redisClient.Get(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	var user models.User
	if err := json.Unmarshal([]byte(userData), &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user data: %v", err)
	}

	return &user, nil
}

// CheckPermission 检查用户是否有权限访问指定路由
func (s *AuthService) CheckPermission(ctx context.Context, userID int64, route string) (bool, error) {
	// 1. 检查路由是否在白名单中
	whitelisted, err := s.checkRouteWhitelist(ctx, route)
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
	redisKey := fmt.Sprintf("user_permissions_%d", userID)
	if permissions, err := s.redisClient.Get(ctx, redisKey).Result(); err == nil {
		var permissionList []models.Permission
		if err := json.Unmarshal([]byte(permissions), &permissionList); err == nil {
			s.userPermissionsCache.Store(userID, permissionList)
			return s.matchRoute(permissionList, route), nil
		}
	}

	// 4. 从数据库获取用户权限
	permissions, err := s.getUserPermissionsFromDB(ctx, userID)
	if err != nil {
		return false, err
	}

	// 更新缓存
	s.userPermissionsCache.Store(userID, permissions)
	permissionsJSON, _ := json.Marshal(permissions)
	s.redisClient.Set(ctx, fmt.Sprintf("user_permissions_%d", userID), permissionsJSON, 24*time.Hour)

	return s.matchRoute(permissions, route), nil
}

// CacheUserPermissions 缓存用户权限信息
func (s *AuthService) CacheUserPermissions(ctx context.Context, userID int64) error {
	permissions, err := s.getUserPermissionsFromDB(ctx, userID)
	if err != nil {
		return err
	}

	// 更新内存缓存
	s.userPermissionsCache.Store(userID, permissions)

	// 更新Redis缓存
	permissionsJSON, err := json.Marshal(permissions)
	if err != nil {
		return err
	}
	return s.redisClient.Set(ctx, fmt.Sprintf("user_permissions_%d", userID), permissionsJSON, 24*time.Hour).Err()
}

// AuthMiddleware 创建认证中间件
func (s *AuthService) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// 检查路由是否在白名单中
		route := c.Path()
		whitelisted, err := s.checkRouteWhitelist(c.Context(), route)
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
		user, err := s.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid token",
			})
		}

		// 检查权限
		hasPermission, err := s.CheckPermission(c.Context(), user.ID, route)
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

		// 将用户信息存储在上下文中
		c.Locals("user", user)

		return c.Next()
	}
}

// GetUserFromContext 从Fiber上下文中获取用户信息
func (s *AuthService) GetUserFromContext(c *fiber.Ctx) *models.User {
	user, ok := c.Locals("user").(*models.User)
	if !ok {
		return nil
	}
	return user
}

// 内部辅助方法

// checkRouteWhitelist 检查路由是否在白名单中
func (s *AuthService) checkRouteWhitelist(ctx context.Context, route string) (bool, error) {
	var whitelist models.RouteWhitelist
	result := s.db.Chain().From(&whitelist).Where("route", define.OpEq, route).First(&whitelist)
	if result.Error != nil {
		return false, nil // 路由不在白名单中
	}
	return whitelist.IsAllowed, nil
}

// matchRoute 匹配路由和权限规则
func (s *AuthService) matchRoute(permissions []models.Permission, route string) bool {
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
func (s *AuthService) getUserPermissionsFromDB(ctx context.Context, userID int64) ([]models.Permission, error) {
	var permissions []models.Permission

	// 获取用户直接权限
	result := s.db.Chain().
		Table("user_permissions up").
		Fields("p.*").
		Join("JOIN permissions p ON up.permission_id = p.id").
		Where("up.user_id", define.OpEq, userID).
		And("(up.expired_at IS NULL OR up.expired_at > ?)", define.OpGt, time.Now()).
		List(&permissions)
	if result.Error != nil {
		return nil, result.Error
	}

	// 获取用户角色权限
	var rolePermissions []models.Permission
	result = s.db.Chain().
		Table("user_roles ur").
		Fields("DISTINCT p.*").
		Join("JOIN role_permissions rp ON ur.role_id = rp.role_id").
		Join("JOIN permissions p ON rp.permission_id = p.id").
		Where("ur.user_id", define.OpEq, userID).
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
func (s *AuthService) CreatePermission(ctx context.Context, permission *models.Permission) error {
	result := s.db.Chain().From(permission).Insert(permission)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetPermissionByID 根据ID获取权限
func (s *AuthService) GetPermissionByID(ctx context.Context, id int64) (*models.Permission, error) {
	var permission models.Permission
	result := s.db.Chain().From(&permission).Where("id", define.OpEq, id).First(&permission)
	if result.Error != nil {
		return nil, result.Error
	}
	return &permission, nil
}

// UpdatePermission 更新权限
func (s *AuthService) UpdatePermission(ctx context.Context, permission *models.Permission) error {
	result := s.db.Chain().From(permission).Where("id", define.OpEq, permission.ID).Update(permission)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeletePermission 删除权限
func (s *AuthService) DeletePermission(ctx context.Context, id int64) error {
	result := s.db.Chain().From(&models.Permission{}).Where("id", define.OpEq, id).Delete()
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ListPermissions 获取权限列表
func (s *AuthService) ListPermissions(ctx context.Context, page, pageSize int) ([]models.Permission, int64, error) {
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
func (s *AuthService) CreateRole(ctx context.Context, role *models.Role) error {
	result := s.db.Chain().From(role).Insert(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// GetRoleByID 根据ID获取角色
func (s *AuthService) GetRoleByID(ctx context.Context, id int64) (*models.Role, error) {
	var role models.Role
	result := s.db.Chain().From(&role).Where("id", define.OpEq, id).First(&role)
	if result.Error != nil {
		return nil, result.Error
	}
	return &role, nil
}

// UpdateRole 更新角色
func (s *AuthService) UpdateRole(ctx context.Context, role *models.Role) error {
	result := s.db.Chain().From(role).Where("id", define.OpEq, role.ID).Update(role)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// DeleteRole 删除角色
func (s *AuthService) DeleteRole(ctx context.Context, id int64) error {
	result := s.db.Chain().From(&models.Role{}).Where("id", define.OpEq, id).Delete()
	if result.Error != nil {
		return result.Error
	}
	return nil
}

// ListRoles 获取角色列表
func (s *AuthService) ListRoles(ctx context.Context, page, pageSize int) ([]models.Role, int64, error) {
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
func (s *AuthService) AssignPermissionToRole(ctx context.Context, roleID, permissionID int64) error {
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

	// 清除缓存
	s.rolePermissionsCache.Delete(roleID)

	return nil
}

// RemovePermissionFromRole 从角色中移除权限
func (s *AuthService) RemovePermissionFromRole(ctx context.Context, roleID, permissionID int64) error {
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

// GetRolePermissions 获取角色的所有权限
func (s *AuthService) GetRolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error) {
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
func (s *AuthService) AssignRoleToUser(ctx context.Context, userID, roleID int64) error {
	// 获取角色信息，确保角色存在
	_, err := s.GetRoleByID(ctx, roleID)
	if err != nil {
		return err
	}

	// 创建用户角色关联
	userRole := &models.UserRole{
		UserID:    userID,
		RoleID:    roleID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	result := s.db.Chain().From(userRole).Insert(userRole)
	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	s.userRolesCache.Delete(userID)
	s.userPermissionsCache.Delete(userID)

	return nil
}

// RemoveRoleFromUser 从用户中移除角色
func (s *AuthService) RemoveRoleFromUser(ctx context.Context, userID, roleID int64) error {
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
func (s *AuthService) GetUserRoles(ctx context.Context, userID int64) ([]models.Role, error) {
	// 先从缓存获取
	if roles, ok := s.userRolesCache.Load(userID); ok {
		return roles.([]models.Role), nil
	}

	// 从数据库获取
	var roles []models.Role
	result := s.db.Chain().
		Table("user_roles ur").
		Fields("r.*").
		Join("JOIN roles r ON ur.role_id = r.id").
		Where("ur.user_id", define.OpEq, userID).
		List(&roles)

	if result.Error != nil {
		return nil, result.Error
	}

	// 更新缓存
	s.userRolesCache.Store(userID, roles)

	return roles, nil
}

// 以下是用户权限表的增删改查方法

// AssignPermissionToUser 为用户分配直接权限
func (s *AuthService) AssignPermissionToUser(ctx context.Context, userID, permissionID int64, expiredAt *time.Time) error {
	// 获取权限信息，确保权限存在
	_, err := s.GetPermissionByID(ctx, permissionID)
	if err != nil {
		return err
	}

	// 创建用户权限关联
	userPermission := &models.UserPermission{
		UserID:       userID,
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
	s.userPermissionsCache.Delete(userID)

	return nil
}

// RemovePermissionFromUser 从用户中移除直接权限
func (s *AuthService) RemovePermissionFromUser(ctx context.Context, userID, permissionID int64) error {
	result := s.db.Chain().From(&models.UserPermission{}).
		Where("user_id", define.OpEq, userID).
		And("permission_id", define.OpEq, permissionID).
		Delete()

	if result.Error != nil {
		return result.Error
	}

	// 清除缓存
	s.userPermissionsCache.Delete(userID)

	return nil
}

// GetUserDirectPermissions 获取用户的直接权限
func (s *AuthService) GetUserDirectPermissions(ctx context.Context, userID int64) ([]models.Permission, error) {
	var permissions []models.Permission
	result := s.db.Chain().
		Table("user_permissions up").
		Fields("p.*").
		Join("JOIN permissions p ON up.permission_id = p.id").
		Where("up.user_id", define.OpEq, userID).
		And("(up.expired_at IS NULL OR up.expired_at > ?)", define.OpGt, time.Now()).
		List(&permissions)

	if result.Error != nil {
		return nil, result.Error
	}

	return permissions, nil
}

// 以下是路由白名单表的增删改查方法

// AddRouteWhitelist 添加路由白名单
func (s *AuthService) AddRouteWhitelist(ctx context.Context, route string, isAllowed bool, ipList string) error {
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
func (s *AuthService) UpdateRouteWhitelist(ctx context.Context, id int64, isAllowed bool, ipList string) error {
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
func (s *AuthService) DeleteRouteWhitelist(ctx context.Context, id int64) error {
	result := s.db.Chain().From(&models.RouteWhitelist{}).Where("id", define.OpEq, id).Delete()
	if result.Error != nil {
		return result.Error
	}

	return nil
}

// ListRouteWhitelists 获取路由白名单列表
func (s *AuthService) ListRouteWhitelists(ctx context.Context, page, pageSize int) ([]models.RouteWhitelist, int64, error) {
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
