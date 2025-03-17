package models

import (
	"time"
)

// Permission 权限规则表
type Permission struct {
	ID        int64     `json:"id" gom:"primary_key"`
	Name      string    `json:"name" gom:"size:100;not null"`    // 权限名称
	Route     string    `json:"route" gom:"size:255;not null"`   // 权限路由
	IsEnabled bool      `json:"is_enabled" gom:"default:true"`   // 是否启用
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"` // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"` // 更新时间
	ExpiredAt time.Time `json:"expired_at" gom:"null"`           // 失效时间
}

// Role 角色表
type Role struct {
	ID        int64     `json:"id" gom:"primary_key"`
	Name      string    `json:"name" gom:"size:100;not null"`    // 角色名称
	Type      string    `json:"type" gom:"size:20;not null"`     // 角色类型：user/admin
	IsEnabled bool      `json:"is_enabled" gom:"default:true"`   // 是否启用
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"` // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"` // 更新时间
}

// RolePermission 角色权限关联表
type RolePermission struct {
	ID             int64     `json:"id" gom:"primary_key"`
	RoleID         int64     `json:"role_id" gom:"not null"`          // 角色ID
	PermissionID   int64     `json:"permission_id" gom:"not null"`    // 权限ID
	RoleName       string    `json:"role_name" gom:"size:100"`        // 角色名称
	PermissionName string    `json:"permission_name" gom:"size:100"`  // 权限名称
	CreatedAt      time.Time `json:"created_at" gom:"autoCreateTime"` // 创建时间
	UpdatedAt      time.Time `json:"updated_at" gom:"autoUpdateTime"` // 更新时间
}

// UserRole 用户角色关联表
type UserRole struct {
	ID        int64     `json:"id" gom:"primary_key"`
	UserID    int64     `json:"user_id" gom:"not null"`          // 用户ID
	RoleID    int64     `json:"role_id" gom:"not null"`          // 角色ID
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"` // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"` // 更新时间
}

// UserPermission 用户权限表
type UserPermission struct {
	ID           int64     `json:"id" gom:"primary_key"`
	UserID       int64     `json:"user_id" gom:"not null"`          // 用户ID
	PermissionID int64     `json:"permission_id" gom:"not null"`    // 权限ID
	ExpiredAt    time.Time `json:"expired_at" gom:"null"`           // 权限过期时间
	CreatedAt    time.Time `json:"created_at" gom:"autoCreateTime"` // 创建时间
	UpdatedAt    time.Time `json:"updated_at" gom:"autoUpdateTime"` // 更新时间
}

// RouteWhitelist 路由黑白名单表
type RouteWhitelist struct {
	ID        int64     `json:"id" gom:"primary_key"`
	Route     string    `json:"route" gom:"size:255;not null"`   // 路由
	IsAllowed bool      `json:"is_allowed" gom:"default:true"`   // 是否允许访问
	IPList    string    `json:"ip_list" gom:"size:1000"`         // 允许访问的IP列表，多个IP用逗号分隔
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"` // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"` // 更新时间
}

// User 用户表
type User struct {
	ID        int64     `json:"id" gom:"primary_key"`
	Username  string    `json:"username" gom:"size:100;not null;unique"` // 用户名
	Password  string    `json:"-" gom:"size:255;not null"`               // 密码
	IsEnabled bool      `json:"is_enabled" gom:"default:true"`           // 是否启用
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"`         // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"`         // 更新时间
}
