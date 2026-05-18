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
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// AuthTool 认证工具结构体
type AuthTool struct {
	redisClient             *redis.Client
	db                      *gorm.DB
	userRolesCache          sync.Map
	userPermissionsCache    sync.Map
	userAllowedRoutesCache  sync.Map // 新增：缓存用户已验证通过的具体路由
	rolePermissionsCache    sync.Map
	permissionCacheDuration time.Duration
	config                  *Config
	mu                      sync.RWMutex

	// jwks 是 OAuth IdP 的公钥缓存。Config.OAuthIssuer 为空时此字段为 nil,
	// AuthMiddleware 只走 Redis 路径(向后兼容 anylogin opaque token)。
	jwks *JWKSCache
}

// NewAuthTool 创建新的认证工具实例
func NewAuthTool(config *Config) (*AuthTool, error) {
	// 三种使用形态,Redis/DB 按需初始化:
	//
	//   1. 老的 IdP 内部消费(adminBackend/userLogin):RedisAddr + DBDSN 都配
	//      → opaque token + JWT 双路径都开,AuthMiddleware 能查权限
	//
	//   2. 第三方 Go backend 拿 OAuth JWT 做鉴权:只配 OAuthIssuer
	//      → Redis/DB 跳过初始化,只走 JWT 路径,无任何外部依赖
	//      → 推荐用 NewJWTValidator(issuer) 这个 helper,更直白
	//
	//   3. 中间形态:配 Redis 不配 DB
	//      → 既能验 opaque(查 Redis)又能验 JWT,但不查权限
	//      → 适合不做 RBAC 的服务

	tool := &AuthTool{
		config: config,
	}

	// === Redis(可选)— 配了才初始化,opaque token 路径需要 ===
	if config.RedisAddr != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr:     config.RedisAddr,
			Password: config.RedisPassword,
			DB:       config.RedisDB,
		})
		ctx := context.Background()
		if err := redisClient.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("redis connection failed: %v", err)
		}
		tool.redisClient = redisClient
	}

	// === DB(可选)— 配了才初始化,permission check 路径需要 ===
	if config.DBDSN != "" {
		gormCfg := &gorm.Config{
			Logger: gormlogger.Default.LogMode(gormlogger.Warn),
		}
		if config.Debug {
			gormCfg.Logger = gormlogger.Default.LogMode(gormlogger.Info)
		}
		db, err := gorm.Open(postgres.Open(config.DBDSN), gormCfg)
		if err != nil {
			return nil, fmt.Errorf("database connection failed: %v", err)
		}
		if sqlDB, err := db.DB(); err == nil {
			maxOpen := config.MaxOpenConns
			if maxOpen == 0 {
				maxOpen = 10
			}
			maxIdle := config.MaxIdleConns
			if maxIdle == 0 {
				maxIdle = 5
			}
			lifeSec := config.ConnMaxLifetimeSec
			if lifeSec == 0 {
				lifeSec = 3600
			}
			sqlDB.SetMaxOpenConns(maxOpen)
			sqlDB.SetMaxIdleConns(maxIdle)
			sqlDB.SetConnMaxLifetime(time.Duration(lifeSec) * time.Second)
		}
		tool.db = db
	}

	// 设置默认权限缓存时间
	permissionCacheDuration := config.PermissionCacheDuration
	if permissionCacheDuration == 0 {
		permissionCacheDuration = 4 * time.Hour
	}
	tool.permissionCacheDuration = permissionCacheDuration

	// === JWKS(OAuth Issuer 配了就开)===
	// 不配 OAuthIssuer 且不配 Redis 等于"啥也验不了",直接报错
	if config.OAuthIssuer != "" {
		tool.jwks = NewJWKSCache(config.OAuthIssuer, config.JWKSRefreshInterval, nil)
	}
	if tool.redisClient == nil && tool.jwks == nil {
		return nil, fmt.Errorf("at least one of RedisAddr or OAuthIssuer must be configured")
	}

	return tool, nil
}

// NewJWTValidator 第三方 Go backend 最简用法 — 只想验 userLogin 颁的
// OAuth ES256 JWT,无 Redis、无 DB、无 permission check。
//
// 用法:
//
//	tool, err := authing.NewJWTValidator("https://auth.janyee.com")
//	if err != nil { log.Fatal(err) }
//
//	// 在你的 fiber middleware 里:
//	userID, userType, tenantID, err := tool.ValidateToken(ctx, bearerToken)
//
// 内部就是 NewAuthTool 跑一遍只配 OAuthIssuer 的 Config,封装一下让 API 更直白。
func NewJWTValidator(issuer string) (*AuthTool, error) {
	if issuer == "" {
		return nil, fmt.Errorf("issuer required (e.g. \"https://auth.janyee.com\")")
	}
	return NewAuthTool(&Config{OAuthIssuer: issuer})
}

// ValidateToken 验证用户 token,按形态自动分发:
//
//   - 三段式 base64url(JWT 紧凑序列化)→ 走 ES256 + JWKS 校验,
//     从 claims 取 sub/tenant_id/user_type。前提是 Config.OAuthIssuer 已配置。
//   - 其它形态(opaque token)→ 查 Redis 的 user_id_<t> / user_type_<t> /
//     tenant_id_<t>,这是 anylogin 老的 SetToken 流程。
//
// 这个 dispatch 让消费方应用引入 authing 后,**无论用户拿的是 anylogin
// directLogin 颁发的 opaque token,还是 OAuth /token 颁发的 JWT,都能
// 直接通过同一个 AuthMiddleware**,真正"一站式"。
func (s *AuthTool) ValidateToken(ctx context.Context, token string) (string, string, string, error) {
	if IsJWT(token) && s.jwks != nil {
		return s.validateJWT(ctx, token)
	}

	// Opaque token 路径(向后兼容)— 仅当 Redis 配了才走
	// 第三方用 NewJWTValidator 的场景下 redisClient 是 nil,直接报错
	if s.redisClient == nil {
		if IsJWT(token) {
			return "", "", "", fmt.Errorf("invalid token: JWT validation failed (jwks not configured? check OAuthIssuer)")
		}
		return "", "", "", fmt.Errorf("invalid token: opaque token requires Redis (not configured in this AuthTool instance)")
	}

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

	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userID)

	// 2. 检查用户专属的"快速通行"路由缓存
	// Stage 6 fix #6:把内层 map 换成 *sync.Map,移除 fast-path 写路径上的全局
	// s.mu.Lock 调用,降锁粒度 ↓ 全局锁,↓ 高并发下的 head-of-line 阻塞。
	if allowedRoutes, ok := s.userAllowedRoutesCache.Load(cacheKey); ok {
		if _, allowed := allowedRoutes.(*sync.Map).Load(route); allowed {
			return true, nil
		}
	}

	// 3. 从内存缓存中获取用户权限规则
	var permissionList []models.Permission
	if permissions, ok := s.userPermissionsCache.Load(cacheKey); ok {
		permissionList = permissions.([]models.Permission)
	}

	if len(permissionList) == 0 {

		redisKey := fmt.Sprintf("user_permissions_%s_%s_%s", tenantID, userType, userID)
		if permissionsStr, err := s.redisClient.Get(ctx, redisKey).Result(); err == nil {
			if err := json.Unmarshal([]byte(permissionsStr), &permissionList); err == nil {
				s.userPermissionsCache.Store(cacheKey, permissionList)
			}
		}
		if len(permissionList) == 0 {
			// 5. 从数据库获取用户权限并缓存
			if err := s.CacheUserPermissions(ctx, userID, userType, tenantID); err != nil {
				return false, err
			}
			if permissions, ok := s.userPermissionsCache.Load(cacheKey); ok {
				permissionList = permissions.([]models.Permission)
			} else {
				return false, fmt.Errorf("failed to get user permissions after fetching from db")
			}
		}
	}

	// 6. 匹配路由和权限规则
	if s.matchRoute(permissionList, route) {
		// 7. 命中后填快速通行缓存。LoadOrStore 保证多 goroutine 并发命中时只
		// 创建一次内层 sync.Map,然后两边都 Store 到同一个 map。无需 s.mu。
		inner, _ := s.userAllowedRoutesCache.LoadOrStore(cacheKey, &sync.Map{})
		inner.(*sync.Map).Store(route, struct{}{})
		return true, nil
	}

	return false, nil
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

// ========================================================================
// 中间件分层 — 身份(authentication)跟权限(authorization)解耦
// ========================================================================
//
// 三个 middleware,按职责分:
//
//   IdentityMiddleware()    身份层 — 验 token,把 (user_id, user_type, tenant_id)
//                                      塞进 c.Locals。不查权限,不知道路由意义。
//                                      第三方服务只想拿到"这是谁"用这个就够。
//
//   PermissionMiddleware()  权限层 — 假设 Locals 已经有 identity(必须先过
//                                      IdentityMiddleware 或调用方自己塞),
//                                      调 CheckPermission 决定能否进路由。
//                                      白名单 / 黑名单逻辑也在这层。
//
//   AuthMiddleware()        全套(向后兼容)— = IdentityMiddleware + PermissionMiddleware,
//                                      跟之前行为完全一致,老消费方不动。
//
// 第三方 Go 服务可以挑组合:
//   - 只要身份认证:   app.Use(auth.IdentityMiddleware())
//   - 身份 + 权限:    app.Use(auth.AuthMiddleware())                // 或拆两个
//   - 自带身份层、只要权限: app.Use(myIdentity, auth.PermissionMiddleware())

// IdentityMiddleware 只验 token,不查权限。
//
// 流程:
//   1. 从 `Token` 头取 token
//   2. ValidateToken → 拿 (user_id, user_type, tenant_id)
//        - JWT (ES256) → JWKS 验签 + 解 claims(无 Redis,无 DB)
//        - opaque (UUID-like) → Redis lookup(老 anylogin/admin 路径)
//   3. 写入 c.Locals,c.Next()
//
// 401 触发条件:Token 头缺失 / token 无效 / Redis 没找到 / JWT 验签失败。
// 不会返 403(权限拒绝是 PermissionMiddleware 的事)。
func (s *AuthTool) IdentityMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Get("Token")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Missing authorization token",
			})
		}

		userId, userType, tenantId, err := s.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Invalid token",
			})
		}

		c.Locals("user_id", userId)
		c.Locals("user_type", userType)
		c.Locals("tenant_id", tenantId)

		return c.Next()
	}
}

// PermissionMiddleware 只查权限,假设 Locals 已经有 identity。
//
// 流程:
//   1. checkRouteWhitelist(白/黑名单)→ 白名单直接 Next
//   2. 从 Locals 取 user_id / user_type / tenant_id;没有就 401
//      (说明没过 IdentityMiddleware,这是个 mis-config)
//   3. CheckPermission → 不通过 403
//
// 调用方负责保证 Locals 已经写好;通常的用法是跟 IdentityMiddleware 串联:
//   app.Use(auth.IdentityMiddleware(), auth.PermissionMiddleware())
// 或者直接用 AuthMiddleware(下面)一把梭。
func (s *AuthTool) PermissionMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		route := c.Path()

		whitelisted, err := s.checkRouteWhitelist(route)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error checking route whitelist",
			})
		}
		if whitelisted {
			return c.Next()
		}

		userId, _ := c.Locals("user_id").(string)
		userType, _ := c.Locals("user_type").(string)
		tenantId, _ := c.Locals("tenant_id").(string)
		if userId == "" {
			// Identity 没设 — 调用方忘了在前面挂 IdentityMiddleware
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Missing identity in context (forgot IdentityMiddleware?)",
			})
		}

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

		return c.Next()
	}
}

// AuthMiddleware 全套认证中间件 = Identity + Permission(向后兼容老消费方)。
//
// 旧调用 `app.Use(auth.AuthMiddleware())` 行为不变。
// 想分层用,改成 `app.Use(auth.IdentityMiddleware(), auth.PermissionMiddleware())`,
// 中间可以插自己的中间件(限流、审计、日志等)。
//
// 实现直接 inline Identity + Permission 的步骤(不通过 fiber Next 链调用,
// 那样需要把后者当 Next handler 传,代码更绕)。
func (s *AuthTool) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		route := c.Path()

		// 1. 白名单 — 早期 short-circuit,免取 token
		whitelisted, err := s.checkRouteWhitelist(route)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Error checking route whitelist",
			})
		}
		if whitelisted {
			return c.Next()
		}

		// 2. Identity — 验 token + 写 Locals
		token := c.Get("Token")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Missing authorization token",
			})
		}
		userId, userType, tenantId, err := s.ValidateToken(c.Context(), token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"message": "Invalid token",
			})
		}
		c.Locals("user_id", userId)
		c.Locals("user_type", userType)
		c.Locals("tenant_id", tenantId)

		// 3. Permission — 查权限
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

		return c.Next()
	}
}

// 内部辅助方法

// checkRouteWhitelist 检查路由是否在白名单中。
//
// 顺序:
//   1. 进程内黑名单(config.BlacklistRoutes)— 命中即拒
//   2. 进程内白名单(config.WhitelistRoutes)— 命中即放行
//   3. DB-backed route_whitelists 表 — Stage 6 修复:之前完全没读这张表
func (s *AuthTool) checkRouteWhitelist(route string) (bool, error) {
	s.mu.RLock()
	black := s.config.BlacklistRoutes
	white := s.config.WhitelistRoutes
	s.mu.RUnlock()

	for _, blackRoute := range black {
		if matched, _ := regexp.MatchString(blackRoute, route); matched {
			return false, nil
		}
	}
	for _, whiteRoute := range white {
		if matched, _ := regexp.MatchString(whiteRoute, route); matched {
			return true, nil
		}
	}

	// DB 表(允许运营时动态加白,无需重启)
	if s.db != nil {
		var rows []models.RouteWhitelist
		if err := s.db.Table("route_whitelists").Find(&rows).Error; err == nil {
			for _, r := range rows {
				if !r.IsAllowed {
					continue
				}
				if matched, _ := regexp.MatchString(r.Route, route); matched {
					return true, nil
				}
			}
		}
	}

	return false, nil
}

// matchRoute 匹配路由和权限规则。
//
// 性能优化(Stage 6 fix):分两遍。第一遍只做精确字符串相等,第二遍才走
// regexp。原实现在循环里"先精确再正则",对每条规则都付出 regexp 编译/匹配
// 成本,即便后面有精确命中也已经先做了正则。在权限规则多的场景显著影响 RPS。
func (s *AuthTool) matchRoute(permissions []models.Permission, route string) bool {
	// Pass 1: 全部精确匹配
	for _, permission := range permissions {
		if !permission.IsEnabled {
			continue
		}
		if permission.Route == route {
			return true
		}
	}
	// Pass 2: 正则匹配
	for _, permission := range permissions {
		if !permission.IsEnabled {
			continue
		}
		if matched, err := regexp.MatchString(permission.Route, route); err == nil && matched {
			return true
		}
	}
	return false
}

// getUserPermissionsFromDB 从数据库获取用户权限
func (s *AuthTool) getUserPermissionsFromDB(ctx context.Context, userId string, userType string, tenantID string) ([]models.Permission, error) {
	var permissions []models.Permission
	now := time.Now()

	// 修正版SQL:使用正确的表名 (permissions, user_permissions, role_permissions, user_roles)
	// Stage 6 fix #7:role_permissions 也加上 expired_at 时间过滤,与
	// user_permissions 对齐(原本只 user_permissions 有 TTL 检查,角色权限永不过期)。
	// 同时补上 permission 自身的 expired_at 过滤,确保过期权限不会被读出。
	sql := `
		SELECT p.*
		FROM permissions p
		WHERE p.tenant_id = $1
		  AND p.is_enabled = true
		  AND (p.expired_at IS NULL OR p.expired_at > $4)
		  AND (
			-- 直接用户权限
			EXISTS (
				SELECT 1
				FROM user_permissions up
				WHERE up.permission_id = p.id
				  AND up.user_id = $2
				  AND up.user_type = $3
				  AND up.tenant_id = $1
				  AND (up.expired_at IS NULL OR up.expired_at > $4)
			)
			-- 通过角色继承的权限
			OR EXISTS (
				SELECT 1
				FROM role_permissions rp
				JOIN user_roles ur ON rp.role_id = ur.role_id
				WHERE rp.permission_id = p.id
				  AND ur.user_id = $2
				  AND ur.user_type = $3
				  AND ur.tenant_id = $1
				  AND rp.tenant_id = $1
				  AND (rp.expired_at IS NULL OR rp.expired_at > $4)
			)
		)
	`

	if err := s.db.WithContext(ctx).Raw(sql, tenantID, userId, userType, now).Scan(&permissions).Error; err != nil {
		return nil, err
	}

	return permissions, nil
}

// clearAllUserPermissionCaches 重置每用户的权限快照(包括 fast-path 路由缓存)。
// 用在权限规则本身被 CRUD 之后,因为不知道哪些用户可能持有受影响的规则。
//
// Stage 6 fix #3:之前 CreatePermission/Update/Delete 不做任何缓存清理,
// 改了 permission 后已登录用户最长 4h(permissionCacheDuration)看不到。
func (s *AuthTool) clearAllUserPermissionCaches() {
	s.userPermissionsCache.Range(func(k, _ any) bool {
		s.userPermissionsCache.Delete(k)
		return true
	})
	s.userAllowedRoutesCache.Range(func(k, _ any) bool {
		s.userAllowedRoutesCache.Delete(k)
		return true
	})
	// Redis 那一层我们暂留 — 它仍按 permissionCacheDuration 过期。下次内存
	// miss 走 Redis 的 4h-旧数据 → 立即又走 DB,只多 1 次 Redis 读,不破契约。
}

// clearUsersWithRole 清除已知缓存中持有指定角色的所有用户的权限缓存。
//
// Stage 6 fix #4:AssignPermissionToRole / RemovePermissionFromRole 之前
// 只清自己的 rolePermissionsCache,但用户的 userPermissionsCache 是按
// (tenant,type,user) 缓存的,不会自动失效。此处遍历缓存找到受影响的用户。
//
// 局限:只覆盖"角色已被缓存过"的用户。完美方案要查 user_roles 表找全部
// 持有该角色的用户;此处保留为 future enhancement。
func (s *AuthTool) clearUsersWithRole(roleID int64) {
	s.userRolesCache.Range(func(k, v any) bool {
		roles, ok := v.([]models.Role)
		if !ok {
			return true
		}
		for _, r := range roles {
			if r.ID == roleID {
				s.userPermissionsCache.Delete(k)
				s.userAllowedRoutesCache.Delete(k)
				return true
			}
		}
		return true
	})
}

// 以下是权限表的增删改查方法

// CreatePermission 创建权限
func (s *AuthTool) CreatePermission(permission *models.Permission) error {
	if err := s.db.Create(permission).Error; err != nil {
		return err
	}
	s.clearAllUserPermissionCaches()
	return nil
}

// GetPermissionByID 根据ID获取权限
func (s *AuthTool) GetPermissionByID(id int64) (*models.Permission, error) {
	var permission models.Permission
	if err := s.db.Where("id = ?", id).First(&permission).Error; err != nil {
		return nil, err
	}
	return &permission, nil
}

// UpdatePermission 更新权限
func (s *AuthTool) UpdatePermission(permission *models.Permission) error {
	if err := s.db.Save(permission).Error; err != nil {
		return err
	}
	s.clearAllUserPermissionCaches()
	return nil
}

// DeletePermission 删除权限
func (s *AuthTool) DeletePermission(id int64) error {
	if err := s.db.Where("id = ?", id).Delete(&models.Permission{}).Error; err != nil {
		return err
	}
	s.clearAllUserPermissionCaches()
	return nil
}

// ListPermissions 获取权限列表
func (s *AuthTool) ListPermissions(page, pageSize int) ([]models.Permission, int64, error) {
	var permissions []models.Permission

	// 获取总数
	var total int64
	if err := s.db.Model(&models.Permission{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	if err := s.db.Model(&models.Permission{}).
		Limit(pageSize).Offset((page - 1) * pageSize).
		Find(&permissions).Error; err != nil {
		return nil, 0, err
	}

	return permissions, total, nil
}

// 以下是角色表的增删改查方法

// CreateRole 创建角色
func (s *AuthTool) CreateRole(role *models.Role) error {
	return s.db.Create(role).Error
}

// GetRoleByID 根据ID获取角色
func (s *AuthTool) GetRoleByID(id int64) (*models.Role, error) {
	var role models.Role
	if err := s.db.Where("id = ?", id).First(&role).Error; err != nil {
		return nil, err
	}
	return &role, nil
}

// UpdateRole 更新角色
func (s *AuthTool) UpdateRole(role *models.Role) error {
	return s.db.Save(role).Error
}

// DeleteRole 删除角色
func (s *AuthTool) DeleteRole(id int64) error {
	return s.db.Where("id = ?", id).Delete(&models.Role{}).Error
}

// ListRoles 获取角色列表
func (s *AuthTool) ListRoles(page, pageSize int) ([]models.Role, int64, error) {
	var roles []models.Role

	var total int64
	if err := s.db.Model(&models.Role{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := s.db.Model(&models.Role{}).
		Limit(pageSize).Offset((page - 1) * pageSize).
		Find(&roles).Error; err != nil {
		return nil, 0, err
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

	if err := s.db.Create(rolePermission).Error; err != nil {
		return err
	}

	// 清除缓存
	s.rolePermissionsCache.Delete(roleID)
	// Stage 6 fix #4:级联清持有该角色的用户的权限缓存
	s.clearUsersWithRole(roleID)

	return nil
}

// RemovePermissionFromRole 从角色中移除权限
func (s *AuthTool) RemovePermissionFromRole(roleID, permissionID int64) error {
	if err := s.db.Where("role_id = ? AND permission_id = ?", roleID, permissionID).
		Delete(&models.RolePermission{}).Error; err != nil {
		return err
	}

	// 清除缓存
	s.rolePermissionsCache.Delete(roleID)
	// Stage 6 fix #4:级联清持有该角色的用户的权限缓存
	s.clearUsersWithRole(roleID)

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
	if err := s.db.WithContext(ctx).
		Table("role_permissions rp").
		Select("p.*").
		Joins("JOIN permissions p ON rp.permission_id = p.id").
		Where("rp.role_id = ?", roleID).
		Find(&permissions).Error; err != nil {
		return nil, err
	}

	// 更新缓存
	s.rolePermissionsCache.Store(roleID, permissions)

	return permissions, nil
}

// 以下是用户角色关联表的增删改查方法

// AssignRoleToUser 为用户分配角色
func (s *AuthTool) AssignRoleToUser(ctx context.Context, userId string, userType string, tenantID string, roleID int64) error {
	// 获取角色信息，确保角色存在
	_, err := s.GetRoleByID(roleID)
	if err != nil {
		return err
	}

	// 创建用户角色关联
	userRole := &models.UserRole{
		UserID:   userId,
		UserType: userType,
		RoleID:   roleID,
		// TenantID is missing here, let's assume it should be set
		TenantID:  tenantID,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := s.db.WithContext(ctx).Create(userRole).Error; err != nil {
		return err
	}

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userId)
	s.userRolesCache.Delete(cacheKey)
	s.userPermissionsCache.Delete(cacheKey)
	s.userAllowedRoutesCache.Delete(cacheKey) // 新增：清除快速通行缓存

	return nil
}

// RemoveRoleFromUser 从用户中移除角色
func (s *AuthTool) RemoveRoleFromUser(ctx context.Context, userID string, userType string, tenantID string, roleID int64) error {
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND user_type = ? AND role_id = ? AND tenant_id = ?",
			userID, userType, roleID, tenantID).
		Delete(&models.UserRole{}).Error; err != nil {
		return err
	}

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userID)
	s.userRolesCache.Delete(cacheKey)
	s.userPermissionsCache.Delete(cacheKey)
	s.userAllowedRoutesCache.Delete(cacheKey) // 新增：清除快速通行缓存

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

	var roles []models.Role
	if err := s.db.WithContext(ctx).Raw(sql, userId, userType, tenantID, tenantID).Scan(&roles).Error; err != nil {
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
func (s *AuthTool) AssignPermissionToUser(ctx context.Context, userId string, userType string, tenantID string, permissionID int64, expiredAt *time.Time) error {
	// 获取权限信息，确保权限存在
	_, err := s.GetPermissionByID(permissionID)
	if err != nil {
		return err
	}

	// 创建用户权限关联
	userPermission := &models.UserPermission{
		UserID:       userId,
		UserType:     userType,
		TenantID:     tenantID,
		PermissionID: permissionID,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// 如果提供了过期时间，则设置(指针类型,nil 表示永久)
	if expiredAt != nil {
		userPermission.ExpiredAt = expiredAt
	}

	if err := s.db.WithContext(ctx).Create(userPermission).Error; err != nil {
		return err
	}

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userId)
	s.userPermissionsCache.Delete(cacheKey)
	s.userAllowedRoutesCache.Delete(cacheKey) // 新增：清除快速通行缓存

	return nil
}

// RemovePermissionFromUser 从用户中移除直接权限
func (s *AuthTool) RemovePermissionFromUser(ctx context.Context, userId string, userType string, tenantID string, permissionID int64) error {
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND user_type = ? AND permission_id = ? AND tenant_id = ?",
			userId, userType, permissionID, tenantID).
		Delete(&models.UserPermission{}).Error; err != nil {
		return err
	}

	// 清除缓存
	cacheKey := fmt.Sprintf("%s_%s_%s", tenantID, userType, userId)
	s.userPermissionsCache.Delete(cacheKey)
	s.userAllowedRoutesCache.Delete(cacheKey) // 新增：清除快速通行缓存

	return nil
}

// GetUserDirectPermissions 获取用户的直接权限
func (s *AuthTool) GetUserDirectPermissions(ctx context.Context, userId string, userType string) ([]models.Permission, error) {
	var permissions []models.Permission
	now := time.Now()

	if err := s.db.WithContext(ctx).
		Table("permissions").
		Joins("JOIN user_permissions ON user_permissions.permission_id = permissions.id").
		Where("user_permissions.user_id = ?", userId).
		Where("user_permissions.user_type = ?", userType).
		Where("user_permissions.expired_at IS NULL OR user_permissions.expired_at > ?", now).
		Find(&permissions).Error; err != nil {
		return nil, err
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

	return s.db.WithContext(ctx).Create(whitelist).Error
}

// UpdateRouteWhitelist 更新路由白名单
func (s *AuthTool) UpdateRouteWhitelist(ctx context.Context, id int64, isAllowed bool, ipList string) error {
	// 只更新 is_allowed / ip_list / updated_at 三列,避免清空其它字段
	return s.db.WithContext(ctx).Model(&models.RouteWhitelist{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"is_allowed": isAllowed,
			"ip_list":    ipList,
			"updated_at": time.Now(),
		}).Error
}

// DeleteRouteWhitelist 删除路由白名单
func (s *AuthTool) DeleteRouteWhitelist(id int64) error {
	return s.db.Where("id = ?", id).Delete(&models.RouteWhitelist{}).Error
}

// ListRouteWhitelists 获取路由白名单列表
func (s *AuthTool) ListRouteWhitelists(page, pageSize int) ([]models.RouteWhitelist, int64, error) {
	var whitelists []models.RouteWhitelist

	var total int64
	if err := s.db.Model(&models.RouteWhitelist{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	if err := s.db.Model(&models.RouteWhitelist{}).
		Limit(pageSize).Offset((page - 1) * pageSize).
		Find(&whitelists).Error; err != nil {
		return nil, 0, err
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
	q := s.db.WithContext(ctx).Table("permissions").Where("tenant_id = ?", tenantID)

	// 添加过滤条件
	for k, v := range filter {
		q = q.Where(fmt.Sprintf("%s = ?", k), v)
	}

	// 获取总数
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count permissions: %v", err)
	}

	// 获取分页数据
	if err := q.Limit(pageSize).Offset((page - 1) * pageSize).Find(&permissions).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get permissions: %v", err)
	}

	return permissions, total, nil
}

// GetRoles 获取角色列表
func (s *AuthTool) GetRoles(ctx context.Context, page int, pageSize int, tenantID string, filter map[string]interface{}) ([]models.Role, int64, error) {
	var roles []models.Role

	q := s.db.WithContext(ctx).Table("roles").Where("tenant_id = ?", tenantID)

	for k, v := range filter {
		q = q.Where(fmt.Sprintf("%s = ?", k), v)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to count roles: %v", err)
	}

	if err := q.Limit(pageSize).Offset((page - 1) * pageSize).Find(&roles).Error; err != nil {
		return nil, 0, fmt.Errorf("failed to get roles: %v", err)
	}

	return roles, total, nil
}

// CreateTenant 创建新租户
func (s *AuthTool) CreateTenant(ctx context.Context, tenantID, name, description string) error {
	tenant := models.NewTenant(tenantID, name, description)
	return s.db.WithContext(ctx).Create(tenant).Error
}

// GetTenant 获取租户信息
func (s *AuthTool) GetTenant(ctx context.Context, tenantID string) (*models.Tenant, error) {
	var tenant models.Tenant
	if err := s.db.WithContext(ctx).
		Where("tenant_id = ?", tenantID).
		First(&tenant).Error; err != nil {
		return nil, err
	}
	return &tenant, nil
}

// UpdateTenant 更新租户信息
func (s *AuthTool) UpdateTenant(ctx context.Context, tenant *models.Tenant) error {
	tenant.UpdatedAt = time.Now()
	return s.db.WithContext(ctx).Save(tenant).Error
}

// DeleteTenant 删除租户
func (s *AuthTool) DeleteTenant(ctx context.Context, tenantID string) error {
	tenant, err := s.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	return s.db.WithContext(ctx).Delete(tenant).Error
}

// GetTenants 获取租户列表
func (s *AuthTool) GetTenants(ctx context.Context, page, pageSize int, condition map[string]interface{}) ([]models.Tenant, int64, error) {
	var tenants []models.Tenant

	// 构建查询
	q := s.db.WithContext(ctx).Model(&models.Tenant{})

	// 添加查询条件
	for k, v := range condition {
		q = q.Where(fmt.Sprintf("%s = ?", k), v)
	}

	// 获取总数
	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	if err := q.Offset((page - 1) * pageSize).Limit(pageSize).Find(&tenants).Error; err != nil {
		return nil, 0, err
	}

	return tenants, total, nil
}
