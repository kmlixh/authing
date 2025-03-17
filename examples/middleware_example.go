package main

import (
	"log"

	"authing"

	"github.com/gofiber/fiber/v2"
	"github.com/kmlixh/gom/v4/define"
)

func main() {
	// 初始化认证服务
	config := &authing.Config{
		RedisAddr:     "localhost:6379",
		RedisPassword: "",
		RedisDB:       0,
		DBDriver:      "postgres",
		DBDSN:         "host=localhost port=5432 user=postgres password=postgres dbname=auth_db sslmode=disable",
		DBOptions: &define.DBOptions{
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
