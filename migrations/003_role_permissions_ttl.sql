-- ============================================
-- 003 - 给 role_permissions 加 expired_at,与 user_permissions 对齐
-- 同时把 role_permissions 缺失的 role_name / permission_name 名义列对齐 model
-- 创建日期: 2026-05-15
-- ============================================

-- 1. expired_at:支持给"角色↔权限"绑定加时效(临时授权)
ALTER TABLE role_permissions
    ADD COLUMN IF NOT EXISTS expired_at TIMESTAMP WITH TIME ZONE;

CREATE INDEX IF NOT EXISTS idx_role_permissions_expired_at
    ON role_permissions(expired_at)
    WHERE expired_at IS NOT NULL;

COMMENT ON COLUMN role_permissions.expired_at
    IS '权限过期时间;NULL 表示永久。读取时 SQL 应过滤 expired_at IS NULL OR expired_at > now()';

-- 2. role_name / permission_name:Go model 已声明,补齐物理列
ALTER TABLE role_permissions
    ADD COLUMN IF NOT EXISTS role_name       VARCHAR(100),
    ADD COLUMN IF NOT EXISTS permission_name VARCHAR(100);

COMMENT ON COLUMN role_permissions.role_name
    IS '冗余字段,便于 admin 列表展示无需 JOIN;由应用层在 INSERT/UPDATE 时维护';
COMMENT ON COLUMN role_permissions.permission_name
    IS '同上';
