# Authing - 基于 Golang 的认证授权服务

Authing 是一个基于 Golang 的认证授权服务，使用三级缓存（内存缓存 + Redis 缓存 + 数据库）来快速响应认证和授权请求。它提供了用户认证、权限管理和路由保护等功能。

## 技术栈

- HTTP 框架：[Fiber](https://github.com/gofiber/fiber)
- 数据库操作：[gom/v4](https://github.com/kmlixh/gom/v4)
- 缓存：[go-redis/v9](https://github.com/redis/go-redis/v9) - 最新版本的 Redis 客户端，支持 Redis 6.0+ 的所有功能

## 核心功能

1. **用户认证**：验证用户 token 的有效性
2. **权限管理**：基于角色和权限的访问控制
3. **三级缓存**：内存缓存 + Redis 缓存 + 数据库
4. **路由保护**：通过中间件保护 API 路由
5. **白名单管理**：支持路由白名单，允许匿名访问

## 数据模型

### 数据库表结构

1. **权限表 (permissions)**
   - 权限 ID
   - 权限名称
   - 权限路由（支持正则匹配）
   - 是否启用
   - 创建时间
   - 更新时间
   - 失效时间（可为空）

2. **角色表 (roles)**
   - 角色 ID
   - 角色名称
   - 角色类型（user/admin）
   - 是否启用
   - 创建时间
   - 更新时间

3. **角色权限表 (role_permissions)**
   - ID
   - 角色 ID
   - 权限 ID
   - 角色名称
   - 权限名称
   - 创建时间
   - 更新时间

4. **用户角色表 (user_roles)**
   - ID
   - 用户 ID
   - 角色 ID
   - 创建时间
   - 更新时间

5. **用户权限表 (user_permissions)**
   - ID
   - 用户 ID
   - 权限 ID
   - 创建时间
   - 更新时间
   - 失效时间（可为空）

6. **路由白名单表 (route_whitelists)**
   - ID
   - 路由
   - 是否允许匿名访问
   - 允许访问的 IP 地址
   - 创建时间
   - 更新时间

## 代码结构

### 主要组件

1. **AuthService**：认证服务的核心结构体，包含 Redis 客户端、数据库连接和内存缓存
2. **Config**：配置结构体，包含 Redis 和数据库的配置信息
3. **中间件**：用于保护 API 路由的 Fiber 中间件

### 缓存策略

Authing 使用三级缓存策略来提高性能：

1. **内存缓存**：使用 `sync.Map` 存储用户权限、角色权限和用户角色信息
2. **Redis 缓存**：存储用户 token 和权限信息，设置 24 小时过期时间
3. **数据库**：作为最终的数据源

### 权限检查流程

1. 检查路由是否在白名单中
2. 从内存缓存中获取用户权限
3. 如果内存缓存未命中，从 Redis 缓存获取
4. 如果 Redis 缓存未命中，从数据库获取并更新缓存
5. 匹配用户权限和请求路由

## 使用方法

### 初始化

```go
config := &authing.Config{
    // Redis 配置
    RedisAddr:     "localhost:6379",  // Redis 服务器地址
    RedisPassword: "",                // Redis 密码，如果没有设置则为空
    RedisDB:       0,                 // Redis 数据库编号，默认为 0
    
    // 数据库配置
    DBDriver:      "postgres",
    DBDSN:         "host=localhost port=5432 user=postgres password=postgres dbname=auth_db sslmode=disable",
    DBOptions:     &define.DBOptions{
        MaxOpenConns:    10,
        MaxIdleConns:    5,
        ConnMaxLifetime: 3600,
        Debug:           true,
    },
}

authService, err := authing.NewAuthService(config)
if err != nil {
    log.Fatalf("Failed to initialize auth service: %v", err)
}
```

### 添加中间件

```go
app := fiber.New()

// 使用认证中间件
app.Use(authService.AuthMiddleware())
```

### 在路由处理器中获取用户信息

```go
app.Get("/api/protected", func(c *fiber.Ctx) error {
    // 从上下文中获取用户信息
    user := authService.GetUserFromContext(c)
    return c.JSON(fiber.Map{
        "message": "Protected route accessed successfully",
        "user":    user,
    })
})
```

### 缓存用户权限

```go
// 用户登录成功后，缓存用户权限
err := authService.CacheUserPermissions(ctx, user.ID)
if err != nil {
    // 处理错误
}
```

### Redis 缓存键

Authing 在 Redis 中使用以下键格式：

- `user_token_{token}` - 存储用户 token 信息
- `user_permissions_{userID}` - 存储用户权限信息

所有 Redis 缓存默认设置 24 小时过期时间。

## API 参考

### AuthService

#### `NewAuthService(config *Config) (*AuthService, error)`

创建新的认证服务实例。

#### `ValidateToken(ctx context.Context, token string) (*models.User, error)`

验证用户 token 的有效性，返回用户信息。

#### `CheckPermission(ctx context.Context, userID int64, route string) (bool, error)`

检查用户是否有权限访问指定路由。

#### `CacheUserPermissions(ctx context.Context, userID int64) error`

缓存用户的权限信息。

#### `AuthMiddleware() fiber.Handler`

创建用于保护 API 路由的 Fiber 中间件。

#### `GetUserFromContext(c *fiber.Ctx) *models.User`

从 Fiber 上下文中获取用户信息。

### 权限管理

#### `CreatePermission(ctx context.Context, permission *models.Permission) error`

创建新的权限。

#### `GetPermissionByID(ctx context.Context, id int64) (*models.Permission, error)`

根据 ID 获取权限。

#### `UpdatePermission(ctx context.Context, permission *models.Permission) error`

更新权限信息。

#### `DeletePermission(ctx context.Context, id int64) error`

删除权限。

#### `ListPermissions(ctx context.Context, page, pageSize int) ([]models.Permission, int64, error)`

获取权限列表，支持分页。

### 角色管理

#### `CreateRole(ctx context.Context, role *models.Role) error`

创建新的角色。

#### `GetRoleByID(ctx context.Context, id int64) (*models.Role, error)`

根据 ID 获取角色。

#### `UpdateRole(ctx context.Context, role *models.Role) error`

更新角色信息。

#### `DeleteRole(ctx context.Context, id int64) error`

删除角色。

#### `ListRoles(ctx context.Context, page, pageSize int) ([]models.Role, int64, error)`

获取角色列表，支持分页。

### 角色权限管理

#### `AssignPermissionToRole(ctx context.Context, roleID, permissionID int64) error`

为角色分配权限。

#### `RemovePermissionFromRole(ctx context.Context, roleID, permissionID int64) error`

从角色中移除权限。

#### `GetRolePermissions(ctx context.Context, roleID int64) ([]models.Permission, error)`

获取角色的所有权限。

### 用户角色管理

#### `AssignRoleToUser(ctx context.Context, userID, roleID int64) error`

为用户分配角色。

#### `RemoveRoleFromUser(ctx context.Context, userID, roleID int64) error`

从用户中移除角色。

#### `GetUserRoles(ctx context.Context, userID int64) ([]models.Role, error)`

获取用户的所有角色。

### 用户权限管理

#### `AssignPermissionToUser(ctx context.Context, userID, permissionID int64, expiredAt *time.Time) error`

为用户分配直接权限，可设置过期时间。

#### `RemovePermissionFromUser(ctx context.Context, userID, permissionID int64) error`

从用户中移除直接权限。

#### `GetUserDirectPermissions(ctx context.Context, userID int64) ([]models.Permission, error)`

获取用户的直接权限。

### 路由白名单管理

#### `AddRouteWhitelist(ctx context.Context, route string, isAllowed bool, ipList string) error`

添加路由白名单，可设置允许访问的 IP 列表。

#### `UpdateRouteWhitelist(ctx context.Context, id int64, isAllowed bool, ipList string) error`

更新路由白名单。

#### `DeleteRouteWhitelist(ctx context.Context, id int64) error`

删除路由白名单。

#### `ListRouteWhitelists(ctx context.Context, page, pageSize int) ([]models.RouteWhitelist, int64, error)`

获取路由白名单列表，支持分页。

## 示例

完整示例请参考 `examples/middleware_example.go`：

```go
package main

import (
    "log"

    "authing"
    "authing/models"

    "github.com/gofiber/fiber/v2"
    "github.com/kmlixh/gom/v4/define"
)

func main() {
    // 初始化认证服务
    config := &authing.Config{
        // Redis 配置
        RedisAddr:     "localhost:6379",  // Redis 服务器地址
        RedisPassword: "",                // Redis 密码，如果没有设置则为空
        RedisDB:       0,                 // Redis 数据库编号，默认为 0
        
        // 数据库配置
        DBDriver:      "postgres",
        DBDSN:         "host=localhost port=5432 user=postgres password=postgres dbname=auth_db sslmode=disable",
        DBOptions:     &define.DBOptions{
            MaxOpenConns:    10,
            MaxIdleConns:    5,
            ConnMaxLifetime: 3600,
            Debug:           true,
        },
    }

    authService, err := authing.NewAuthService(config)
    if err != nil {
        log.Fatalf("Failed to initialize auth service: %v", err)
    }

    // 创建 Fiber 应用
    app := fiber.New()

    // 使用认证中间件
    app.Use(authService.AuthMiddleware())

    // 受保护的路由
    app.Get("/api/protected", func(c *fiber.Ctx) error {
        // 从上下文中获取用户信息
        user := authService.GetUserFromContext(c)
        return c.JSON(fiber.Map{
            "message": "Protected route accessed successfully",
            "user":    user,
        })
    })

    // 启动服务器
    log.Fatal(app.Listen(":3000"))
}
```

## 许可证

MIT