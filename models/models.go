package models

import (
	"time"
)

// Permission 权限规则表
type Permission struct {
	ID        int64     `json:"id" gom:"id,@"`
	TenantID  string    `json:"tenant_id" gom:"tenant_id"`
	Name      string    `json:"name" gom:"name"`
	Route     string    `json:"route" gom:"route"`           // 修正：明确指定列名
	IsEnabled bool      `json:"is_enabled" gom:"is_enabled"` // 修正：明确指定列名
	CreatedAt time.Time `json:"created_at" gom:"created_at"` // 修正：明确指定列名
	UpdatedAt time.Time `json:"updated_at" gom:"updated_at"` // 修正：明确指定列名
	ExpiredAt time.Time `json:"expired_at" gom:"expired_at"` // 修正：明确指定列名
}

// Role 角色表
type Role struct {
	ID        int64     `json:"id" gom:"primary_key"`
	TenantID  string    `json:"tenant_id" gom:"size:50;not null"` // 租户ID
	Name      string    `json:"name" gom:"size:100;not null"`     // 角色名称
	Type      string    `json:"type" gom:"size:20;not null"`      // 角色类型：user/admin
	IsEnabled bool      `json:"is_enabled" gom:"default:true"`    // 是否启用
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"`  // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"`  // 更新时间
}

// RolePermission 角色权限关联表
type RolePermission struct {
	ID             int64     `json:"id" gom:"primary_key"`
	TenantID       string    `json:"tenant_id" gom:"size:50;not null"` // 租户ID
	RoleID         int64     `json:"role_id" gom:"not null"`           // 角色ID
	PermissionID   int64     `json:"permission_id" gom:"not null"`     // 权限ID
	RoleName       string    `json:"role_name" gom:"size:100"`         // 角色名称
	PermissionName string    `json:"permission_name" gom:"size:100"`   // 权限名称
	CreatedAt      time.Time `json:"created_at" gom:"autoCreateTime"`  // 创建时间
	UpdatedAt      time.Time `json:"updated_at" gom:"autoUpdateTime"`  // 更新时间
}

// UserType 用户类型
type UserType struct {
	ID        int64     `json:"id" gom:"primary_key"`
	TenantID  string    `json:"tenant_id" gom:"size:50;not null"` // 租户ID
	Name      string    `json:"name" gom:"size:50;not null"`      // 用户类型名称
	Code      string    `json:"code" gom:"size:50;not null"`      // 用户类型编码
	IsEnabled bool      `json:"is_enabled" gom:"default:true"`    // 是否启用
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"`  // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"`  // 更新时间
}

// UserRole 用户角色关联表
type UserRole struct {
	ID        int64     `json:"id" gom:"primary_key"`
	TenantID  string    `json:"tenant_id" gom:"size:50;not null"` // 租户ID
	UserID    string    `json:"user_id" gom:"not null"`           // 用户ID
	UserType  string    `json:"user_type" gom:"not null"`         // 用户类型
	RoleID    int64     `json:"role_id" gom:"not null"`           // 角色ID
	CreatedAt time.Time `json:"created_at" gom:"autoCreateTime"`  // 创建时间
	UpdatedAt time.Time `json:"updated_at" gom:"autoUpdateTime"`  // 更新时间
}

// UserPermission 用户权限表
type UserPermission struct {
	ID           int64     `json:"id" gom:"primary_key"`
	TenantID     string    `json:"tenant_id" gom:"size:50;not null"` // 租户ID
	UserID       string    `json:"user_id" gom:"not null"`           // 用户ID
	UserType     string    `json:"user_type" gom:"not null"`         // 用户类型
	PermissionID int64     `json:"permission_id" gom:"not null"`     // 权限ID
	ExpiredAt    time.Time `json:"expired_at" gom:"null"`            // 权限过期时间
	CreatedAt    time.Time `json:"created_at" gom:"autoCreateTime"`  // 创建时间
	UpdatedAt    time.Time `json:"updated_at" gom:"autoUpdateTime"`  // 更新时间
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
