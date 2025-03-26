-- Initialize database
-- Create tables
-- Permission table
CREATE TABLE IF NOT EXISTS permissions (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    route VARCHAR(255) NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expired_at TIMESTAMP NULL
);

-- Role table
CREATE TABLE IF NOT EXISTS roles (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(20) NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Role permission relation table
CREATE TABLE IF NOT EXISTS role_permissions (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    role_id INTEGER NOT NULL,
    permission_id INTEGER NOT NULL,
    role_name VARCHAR(100),
    permission_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id),
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

-- User type table
CREATE TABLE IF NOT EXISTS user_types (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    name VARCHAR(50) NOT NULL,
    code VARCHAR(50) NOT NULL,
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User role relation table
CREATE TABLE IF NOT EXISTS user_roles (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    user_type VARCHAR(50) NOT NULL,
    role_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- User permission table
CREATE TABLE IF NOT EXISTS user_permissions (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(50) NOT NULL,
    user_id VARCHAR(50) NOT NULL,
    user_type VARCHAR(50) NOT NULL,
    permission_id INTEGER NOT NULL,
    expired_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (permission_id) REFERENCES permissions(id)
);

-- Route whitelist table
CREATE TABLE IF NOT EXISTS route_whitelists (
    id SERIAL PRIMARY KEY,
    route VARCHAR(255) NOT NULL,
    is_allowed BOOLEAN DEFAULT TRUE,
    ip_list VARCHAR(1000),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test data
-- Insert permissions
INSERT INTO permissions (tenant_id, name, route, is_enabled) VALUES
('test_tenant', 'View User List', '/api/users', TRUE),
('test_tenant', 'View User Detail', '/api/users/\\d+', TRUE),
('test_tenant', 'Create User', '/api/users/create', TRUE),
('test_tenant', 'Edit User', '/api/users/edit', TRUE),
('test_tenant', 'Delete User', '/api/users/delete', TRUE),
('test_tenant', 'Role Management', '/api/roles.*', TRUE),
('test_tenant', 'Permission Management', '/api/permissions.*', TRUE);

-- Insert roles
INSERT INTO roles (tenant_id, name, type, is_enabled) VALUES
('test_tenant', 'Super Admin', 'admin', TRUE),
('test_tenant', 'Normal Admin', 'admin', TRUE),
('test_tenant', 'Normal User', 'user', TRUE),
('test_tenant', 'Guest', 'user', TRUE);

-- Insert role permissions relations
INSERT INTO role_permissions (tenant_id, role_id, permission_id, role_name, permission_name) VALUES
('test_tenant', 1, 1, 'Super Admin', 'View User List'),
('test_tenant', 1, 2, 'Super Admin', 'View User Detail'),
('test_tenant', 1, 3, 'Super Admin', 'Create User'),
('test_tenant', 1, 4, 'Super Admin', 'Edit User'),
('test_tenant', 1, 5, 'Super Admin', 'Delete User'),
('test_tenant', 1, 6, 'Super Admin', 'Role Management'),
('test_tenant', 1, 7, 'Super Admin', 'Permission Management'),
('test_tenant', 2, 1, 'Normal Admin', 'View User List'),
('test_tenant', 2, 2, 'Normal Admin', 'View User Detail'),
('test_tenant', 2, 3, 'Normal Admin', 'Create User'),
('test_tenant', 2, 4, 'Normal Admin', 'Edit User'),
('test_tenant', 3, 1, 'Normal User', 'View User List'),
('test_tenant', 3, 2, 'Normal User', 'View User Detail');

-- Insert user types
INSERT INTO user_types (tenant_id, name, code, is_enabled) VALUES
('test_tenant', 'Employee', 'employee', TRUE),
('test_tenant', 'Customer', 'customer', TRUE),
('test_tenant', 'Partner', 'partner', TRUE);

-- Insert user role relations
INSERT INTO user_roles (tenant_id, user_id, user_type, role_id) VALUES
('test_tenant', 'user1', 'employee', 1),
('test_tenant', 'user2', 'employee', 2),
('test_tenant', 'user3', 'customer', 3),
('test_tenant', 'user4', 'partner', 4);

-- Insert user direct permissions
INSERT INTO user_permissions (tenant_id, user_id, user_type, permission_id, expired_at) VALUES
('test_tenant', 'user3', 'customer', 4, CURRENT_TIMESTAMP + INTERVAL '30 days'),
('test_tenant', 'user4', 'partner', 6, CURRENT_TIMESTAMP + INTERVAL '15 days');

-- Insert route whitelist
INSERT INTO route_whitelists (route, is_allowed, ip_list) VALUES
('/api/public/.*', TRUE, NULL),
('/api/login', TRUE, NULL),
('/api/register', TRUE, NULL),
('/api/admin/.*', FALSE, '192.168.111.1,192.168.111.2'); 