package models

import (
	"time"
)

// Permission 权限规则表
type Permission struct {
	ID        int64  `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID  string `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;index"`
	Name      string `json:"name" gorm:"column:name;size:100;not null"`
	Route     string `json:"route" gorm:"column:route;size:255;not null"`
	IsEnabled bool   `json:"is_enabled" gorm:"column:is_enabled;default:true"`
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
	// ExpiredAt 改为指针:零值 time.Time 写到 PG 会落成实际时间戳而不是 NULL,
	// 让"无过期"语义失效。指针类型确保 nil 真正落库为 NULL。
	ExpiredAt *time.Time `json:"expired_at,omitempty" gorm:"column:expired_at"`
}

// TableName 显式声明表名,避免 gorm 默认的 snake_case 复数推断走偏。
func (Permission) TableName() string { return "permissions" }

// Role 角色表
type Role struct {
	ID        int64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID  string    `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;index"` // 租户ID
	Name      string    `json:"name" gorm:"column:name;size:100;not null"`                // 角色名称
	Type      string    `json:"type" gorm:"column:type;size:20;not null"`                 // 角色类型：user/admin
	IsEnabled bool      `json:"is_enabled" gorm:"column:is_enabled;default:true"`         // 是否启用
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`       // 创建时间
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`       // 更新时间
}

func (Role) TableName() string { return "roles" }

// RolePermission 角色权限关联表
type RolePermission struct {
	ID             int64      `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID       string     `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;index"` // 租户ID
	RoleID         int64      `json:"role_id" gorm:"column:role_id;not null;index"`             // 角色ID
	PermissionID   int64      `json:"permission_id" gorm:"column:permission_id;not null;index"` // 权限ID
	RoleName       string     `json:"role_name" gorm:"column:role_name;size:100"`               // 冗余:角色名称
	PermissionName string     `json:"permission_name" gorm:"column:permission_name;size:100"`   // 冗余:权限名称
	// ExpiredAt 由 003_role_permissions_ttl.sql 加上;nil = 永久。Stage 6 加。
	ExpiredAt *time.Time `json:"expired_at,omitempty" gorm:"column:expired_at"`
	CreatedAt time.Time  `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt time.Time  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

func (RolePermission) TableName() string { return "role_permissions" }

// UserType 用户类型
type UserType struct {
	ID        int64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID  string    `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;index"` // 租户ID
	Name      string    `json:"name" gorm:"column:name;size:50;not null"`                 // 用户类型名称
	Code      string    `json:"code" gorm:"column:code;size:50;not null"`                 // 用户类型编码
	IsEnabled bool      `json:"is_enabled" gorm:"column:is_enabled;default:true"`         // 是否启用
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`       // 创建时间
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`       // 更新时间
}

func (UserType) TableName() string { return "user_types" }

// UserRole 用户角色关联表
type UserRole struct {
	ID        int64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID  string    `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;index"` // 租户ID
	UserID    string    `json:"user_id" gorm:"column:user_id;not null;index"`             // 用户ID
	UserType  string    `json:"user_type" gorm:"column:user_type;not null"`               // 用户类型
	RoleID    int64     `json:"role_id" gorm:"column:role_id;not null;index"`             // 角色ID
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`       // 创建时间
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`       // 更新时间
}

func (UserRole) TableName() string { return "user_roles" }

// UserPermission 用户权限表
type UserPermission struct {
	ID           int64      `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID     string     `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;index"` // 租户ID
	UserID       string     `json:"user_id" gorm:"column:user_id;not null;index"`             // 用户ID
	UserType     string     `json:"user_type" gorm:"column:user_type;not null"`               // 用户类型
	PermissionID int64      `json:"permission_id" gorm:"column:permission_id;not null;index"` // 权限ID
	ExpiredAt    *time.Time `json:"expired_at,omitempty" gorm:"column:expired_at"`            // 过期时间;nil = 永久
	CreatedAt    time.Time  `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt    time.Time  `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

func (UserPermission) TableName() string { return "user_permissions" }

// RouteWhitelist 路由黑白名单表
type RouteWhitelist struct {
	ID        int64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	Route     string    `json:"route" gorm:"column:route;size:255;not null"`        // 路由
	IsAllowed bool      `json:"is_allowed" gorm:"column:is_allowed;default:true"`   // 是否允许访问
	IPList    string    `json:"ip_list" gorm:"column:ip_list;size:1000"`            // 允许访问的IP列表，多个IP用逗号分隔
	CreatedAt time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"` // 创建时间
	UpdatedAt time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"` // 更新时间
}

func (RouteWhitelist) TableName() string { return "route_whitelists" }
