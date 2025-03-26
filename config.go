package authing

import (
	"time"

	"github.com/kmlixh/gom/v4/define"
)

// Config 配置结构体
type Config struct {
	RedisAddr               string
	RedisPassword           string
	RedisDB                 int
	DBDriver                string
	DBDSN                   string
	DBOptions               *define.DBOptions
	PermissionCacheDuration time.Duration // 权限缓存时间，默认为4小时
	// 白名单配置
	WhitelistRoutes []string // 白名单路由列表
	BlacklistRoutes []string // 黑名单路由列表
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

	// 更新数据库配置
	if config.DBDriver != "" {
		s.config.DBDriver = config.DBDriver
	}
	if config.DBDSN != "" {
		s.config.DBDSN = config.DBDSN
	}
	if config.DBOptions != nil {
		s.config.DBOptions = config.DBOptions
	}

	// 更新黑白名单配置
	if config.WhitelistRoutes != nil {
		s.config.WhitelistRoutes = config.WhitelistRoutes
	}
	if config.BlacklistRoutes != nil {
		s.config.BlacklistRoutes = config.BlacklistRoutes
	}

	return nil
}
