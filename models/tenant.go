package models

import (
	"time"
)

// Tenant 租户模型。
//
// 历史:此 struct 之前实现 gom 的 ITableModel 接口(GetPk/PrimaryKey/
// Fields/CreateSql),用于 gom 自动建表。迁到 gorm 后那些方法已删除,表
// 由 userLogin 的 migrations 管理。如果生产环境上需要兜底建表,可以在
// NewAuthTool 里加 `db.AutoMigrate(&Tenant{})`,字段 tag 已经齐全。
type Tenant struct {
	ID          int64     `json:"id" gorm:"column:id;primaryKey;autoIncrement"`
	TenantID    string    `json:"tenant_id" gorm:"column:tenant_id;size:50;not null;uniqueIndex"`
	Name        string    `json:"name" gorm:"column:name;size:255;not null"`
	Description string    `json:"description" gorm:"column:description;type:text"`
	IsEnabled   bool      `json:"is_enabled" gorm:"column:is_enabled;default:true"`
	CreatedAt   time.Time `json:"created_at" gorm:"column:created_at;autoCreateTime"`
	UpdatedAt   time.Time `json:"updated_at" gorm:"column:updated_at;autoUpdateTime"`
}

// TableName 显式声明表名(gorm 会用)。
func (Tenant) TableName() string {
	return "tenants"
}

// NewTenant 创建新租户(IsEnabled = true,CreatedAt/UpdatedAt 由 gorm
// autoCreateTime/autoUpdateTime 自动填,但手动 set 也无害)。
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
