package authing

import (
	"time"
)

// Config 配置结构体
//
// gorm 迁移说明:之前的 `DBOptions *define.DBOptions`(gom 类型)被拆成
// 4 个 first-class 字段(MaxOpenConns/MaxIdleConns/ConnMaxLifetimeSec/Debug),
// 这样调用方不需要 import gom/v4/define。
type Config struct {
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	DBDriver      string
	DBDSN         string

	// 数据库连接池配置(替代之前的 DBOptions)。零值会使用合理默认。
	MaxOpenConns       int  // 默认 10
	MaxIdleConns       int  // 默认 5
	ConnMaxLifetimeSec int  // 默认 3600 (秒)
	Debug              bool // true 时 gormlogger.Mode = Info,否则 Warn

	PermissionCacheDuration time.Duration // 权限缓存时间，默认为4小时
	// 白名单配置
	WhitelistRoutes []string // 白名单路由列表
	BlacklistRoutes []string // 黑名单路由列表

	// OAuthIssuer 是 IdP 的发行者 URL,例如 https://auth.janyee.com。
	// 设置后,authing 会通过 <issuer>/.well-known/openid-configuration 自动发现
	// jwks_uri 并缓存公钥,用于校验 OAuth 颁发的 ES256 access token。
	// 留空则只支持原有的 anylogin opaque token (Redis 查询模式)。
	OAuthIssuer string
	// JWKSRefreshInterval 控制 JWKS 缓存的最大寿命;默认 1h。kid 不在缓存里时
	// 会立即刷新一次(带最短 30s 间隔的 throttle,避免对端被打爆)。
	JWKSRefreshInterval time.Duration
}

// UpdateConfig 更新配置
func (s *AuthTool) UpdateConfig(config *Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 更新Redis配置
	if config.RedisAddr != "" {
		s.config.RedisAddr = config.RedisAddr
	}
	if config.RedisPassword != "" {
		s.config.RedisPassword = config.RedisPassword
	}
	if config.RedisDB != s.config.RedisDB {
		s.config.RedisDB = config.RedisDB
	}

	// 更新数据库配置(注:DSN/驱动改了不会重连,需要重启进程才生效)
	if config.DBDriver != "" {
		s.config.DBDriver = config.DBDriver
	}
	if config.DBDSN != "" {
		s.config.DBDSN = config.DBDSN
	}
	if config.MaxOpenConns != 0 {
		s.config.MaxOpenConns = config.MaxOpenConns
	}
	if config.MaxIdleConns != 0 {
		s.config.MaxIdleConns = config.MaxIdleConns
	}
	if config.ConnMaxLifetimeSec != 0 {
		s.config.ConnMaxLifetimeSec = config.ConnMaxLifetimeSec
	}
	s.config.Debug = config.Debug

	// 更新黑白名单配置
	if config.WhitelistRoutes != nil {
		s.config.WhitelistRoutes = config.WhitelistRoutes
	}
	if config.BlacklistRoutes != nil {
		s.config.BlacklistRoutes = config.BlacklistRoutes
	}

	return nil
}
