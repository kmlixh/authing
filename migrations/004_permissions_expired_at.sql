-- ============================================
-- 004 - 给 permissions 表加 expired_at,补齐 Stage 6 fix #7 漏的 DDL
-- 创建日期: 2026-05-17
-- ============================================
--
-- 背景:
--   Stage 6 fix #7(auth.go getUserPermissionsFromDB)的 SQL 加了
--     AND (p.expired_at IS NULL OR p.expired_at > $4)
--   过滤,确保过期的 permission 不会被读出。
--
--   migration 003 同步给 `role_permissions` 加了 expired_at,但漏了
--   `permissions` 表本身。生产部署后任何 admin 调 /admin/* 都报
--   `ERROR: column p.expired_at does not exist (SQLSTATE 42703)`,
--   接着 CheckPermission 返回 error,authing.AuthMiddleware 返 500。
--
-- 影响:已经在 prod 部署的 authing schema 必须跑这个 migration。

-- 1. expired_at:支持给"租户↔权限规则"加时效(临时启用一段时间后失效)
ALTER TABLE permissions
    ADD COLUMN IF NOT EXISTS expired_at TIMESTAMP WITH TIME ZONE;

-- 2. 加索引,getUserPermissionsFromDB 的 (... > now()) 比较走索引更快
CREATE INDEX IF NOT EXISTS idx_permissions_expired_at
    ON permissions(expired_at)
    WHERE expired_at IS NOT NULL;

COMMENT ON COLUMN permissions.expired_at
    IS '权限过期时间;NULL 表示永久。getUserPermissionsFromDB SQL 过滤 expired_at IS NULL OR expired_at > now()';
