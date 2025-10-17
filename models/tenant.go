package models

import (
	"time"
)

// Tenant 租户模型
type Tenant struct {
	ID          int64     `json:"id" gom:"id,pk"`
	TenantID    string    `json:"tenant_id" gom:"tenant_id"`
	Name        string    `json:"name" gom:"name"`
	Description string    `json:"description" gom:"description"`
	IsEnabled   bool      `json:"is_enabled" gom:"is_enabled"`
	CreatedAt   time.Time `json:"created_at" gom:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" gom:"updated_at"`
}

// TableName 返回表名
func (t *Tenant) TableName() string {
	return "tenants"
}

// GetPk 返回主键名
func (t *Tenant) GetPk() string {
	return "id"
}

// PrimaryKey 返回主键值
func (t *Tenant) PrimaryKey() interface{} {
	return t.ID
}

// Fields 返回所有字段
func (t *Tenant) Fields() []string {
	return []string{"id", "tenant_id", "name", "description", "is_enabled", "created_at", "updated_at"}
}

// CreateSql 实现ITableModel接口
func (t *Tenant) CreateSql(dialect string) string {
	return `CREATE TABLE IF NOT EXISTS tenants (
		id BIGSERIAL PRIMARY KEY,
		tenant_id VARCHAR(50) NOT NULL UNIQUE,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		is_enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
	)`
}

// NewTenant 创建新租户
func NewTenant(tenantID, name, description string) *Tenant {
	now := time.Now()
	return &Tenant{
		TenantID:    tenantID,
		Name:        name,
		Description: description,
		IsEnabled:   true,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}
