-- 初始化测试数据

-- 插入默认租户
INSERT INTO tenants (tenant_id, name, description, is_enabled) VALUES
('test_tenant', '测试租户', '用于测试的租户', true),
('default', '默认租户', '系统默认租户', true)
ON CONFLICT (tenant_id) DO NOTHING;

-- 插入权限数据
INSERT INTO permissions (tenant_id, name, route, is_enabled) VALUES
('test_tenant', '查看用户列表', '/api/users', true),
('test_tenant', '查看用户详情', '/api/users/\\d+', true),
('test_tenant', '创建用户', '/api/users/create', true),
('test_tenant', '编辑用户', '/api/users/edit', true),
('test_tenant', '删除用户', '/api/users/delete', true),
('test_tenant', '角色管理', '/api/roles.*', true),
('test_tenant', '权限管理', '/api/permissions.*', true)
ON CONFLICT DO NOTHING;

-- 插入角色数据
INSERT INTO roles (tenant_id, name, type, is_enabled) VALUES
('test_tenant', '超级管理员', 'admin', true),
('test_tenant', '普通管理员', 'admin', true),
('test_tenant', '普通用户', 'user', true),
('test_tenant', '访客', 'user', true)
ON CONFLICT DO NOTHING;

-- 插入角色权限关联
INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT 'test_tenant', r.id, p.id
FROM roles r, permissions p
WHERE r.name = '超级管理员' AND r.tenant_id = 'test_tenant'
AND p.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT 'test_tenant', r.id, p.id
FROM roles r, permissions p
WHERE r.name = '普通管理员' AND r.tenant_id = 'test_tenant'
AND p.name IN ('查看用户列表', '查看用户详情', '创建用户', '编辑用户')
AND p.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (tenant_id, role_id, permission_id)
SELECT 'test_tenant', r.id, p.id
FROM roles r, permissions p
WHERE r.name = '普通用户' AND r.tenant_id = 'test_tenant'
AND p.name IN ('查看用户列表', '查看用户详情')
AND p.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

-- 插入用户类型
INSERT INTO user_types (tenant_id, name, code, is_enabled) VALUES
('test_tenant', '员工', 'employee', true),
('test_tenant', '客户', 'customer', true),
('test_tenant', '合作伙伴', 'partner', true)
ON CONFLICT DO NOTHING;

-- 插入示例用户角色关联
INSERT INTO user_roles (tenant_id, user_id, user_type, role_id)
SELECT 'test_tenant', 'user1', 'employee', r.id
FROM roles r
WHERE r.name = '超级管理员' AND r.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (tenant_id, user_id, user_type, role_id)
SELECT 'test_tenant', 'user2', 'employee', r.id
FROM roles r
WHERE r.name = '普通管理员' AND r.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (tenant_id, user_id, user_type, role_id)
SELECT 'test_tenant', 'user3', 'customer', r.id
FROM roles r
WHERE r.name = '普通用户' AND r.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

INSERT INTO user_roles (tenant_id, user_id, user_type, role_id)
SELECT 'test_tenant', 'user4', 'partner', r.id
FROM roles r
WHERE r.name = '访客' AND r.tenant_id = 'test_tenant'
ON CONFLICT DO NOTHING;

-- 插入路由白名单
INSERT INTO route_whitelists (route, is_allowed, ip_list) VALUES
('/api/public/.*', true, NULL),
('/api/login', true, NULL),
('/api/register', true, NULL),
('/api/admin/.*', false, '192.168.111.1,192.168.111.2')
ON CONFLICT DO NOTHING; 