-- Seed data for the rw3iss Authentication Server
-- Version: 002
-- Description: Seeds system roles and permissions

-- Insert system permissions

-- User permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'users:create', 'Create Users', 'Permission to create new users', 'users', 'create', 'User Management'),
    (uuid_generate_v4(), 'users:read', 'View Users', 'Permission to view user details', 'users', 'read', 'User Management'),
    (uuid_generate_v4(), 'users:update', 'Update Users', 'Permission to update user information', 'users', 'update', 'User Management'),
    (uuid_generate_v4(), 'users:delete', 'Delete Users', 'Permission to delete users', 'users', 'delete', 'User Management'),
    (uuid_generate_v4(), 'users:list', 'List Users', 'Permission to list users', 'users', 'list', 'User Management'),
    (uuid_generate_v4(), 'users:manage', 'Manage Users', 'Full user management permissions', 'users', 'manage', 'User Management'),
    (uuid_generate_v4(), 'users:invite', 'Invite Users', 'Permission to invite users to organizations', 'users', 'invite', 'User Management');

-- Organization permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'organizations:create', 'Create Organizations', 'Permission to create new organizations', 'organizations', 'create', 'Organization Management'),
    (uuid_generate_v4(), 'organizations:read', 'View Organizations', 'Permission to view organization details', 'organizations', 'read', 'Organization Management'),
    (uuid_generate_v4(), 'organizations:update', 'Update Organizations', 'Permission to update organization information', 'organizations', 'update', 'Organization Management'),
    (uuid_generate_v4(), 'organizations:delete', 'Delete Organizations', 'Permission to delete organizations', 'organizations', 'delete', 'Organization Management'),
    (uuid_generate_v4(), 'organizations:list', 'List Organizations', 'Permission to list organizations', 'organizations', 'list', 'Organization Management'),
    (uuid_generate_v4(), 'organizations:manage', 'Manage Organizations', 'Full organization management permissions', 'organizations', 'manage', 'Organization Management');

-- Role permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'roles:create', 'Create Roles', 'Permission to create new roles', 'roles', 'create', 'Role Management'),
    (uuid_generate_v4(), 'roles:read', 'View Roles', 'Permission to view role details', 'roles', 'read', 'Role Management'),
    (uuid_generate_v4(), 'roles:update', 'Update Roles', 'Permission to update role information', 'roles', 'update', 'Role Management'),
    (uuid_generate_v4(), 'roles:delete', 'Delete Roles', 'Permission to delete roles', 'roles', 'delete', 'Role Management'),
    (uuid_generate_v4(), 'roles:list', 'List Roles', 'Permission to list roles', 'roles', 'list', 'Role Management'),
    (uuid_generate_v4(), 'roles:assign', 'Assign Roles', 'Permission to assign roles to users', 'roles', 'assign', 'Role Management');

-- Permission permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'permissions:read', 'View Permissions', 'Permission to view permission details', 'permissions', 'read', 'Permission Management'),
    (uuid_generate_v4(), 'permissions:list', 'List Permissions', 'Permission to list permissions', 'permissions', 'list', 'Permission Management');

-- Auction permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'auctions:create', 'Create Auctions', 'Permission to create new auctions', 'auctions', 'create', 'Auction Management'),
    (uuid_generate_v4(), 'auctions:read', 'View Auctions', 'Permission to view auction details', 'auctions', 'read', 'Auction Management'),
    (uuid_generate_v4(), 'auctions:update', 'Update Auctions', 'Permission to update auction information', 'auctions', 'update', 'Auction Management'),
    (uuid_generate_v4(), 'auctions:delete', 'Delete Auctions', 'Permission to delete auctions', 'auctions', 'delete', 'Auction Management'),
    (uuid_generate_v4(), 'auctions:list', 'List Auctions', 'Permission to list auctions', 'auctions', 'list', 'Auction Management'),
    (uuid_generate_v4(), 'auctions:manage', 'Manage Auctions', 'Full auction management permissions', 'auctions', 'manage', 'Auction Management'),
    (uuid_generate_v4(), 'auctions:approve', 'Approve Auctions', 'Permission to approve auctions', 'auctions', 'approve', 'Auction Management');

-- Bid permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'bids:create', 'Place Bids', 'Permission to place bids on auctions', 'bids', 'create', 'Bidding'),
    (uuid_generate_v4(), 'bids:read', 'View Bids', 'Permission to view bid details', 'bids', 'read', 'Bidding'),
    (uuid_generate_v4(), 'bids:list', 'List Bids', 'Permission to list bids', 'bids', 'list', 'Bidding');

-- Item permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'items:create', 'Create Items', 'Permission to create items for auction', 'items', 'create', 'Item Management'),
    (uuid_generate_v4(), 'items:read', 'View Items', 'Permission to view item details', 'items', 'read', 'Item Management'),
    (uuid_generate_v4(), 'items:update', 'Update Items', 'Permission to update item information', 'items', 'update', 'Item Management'),
    (uuid_generate_v4(), 'items:delete', 'Delete Items', 'Permission to delete items', 'items', 'delete', 'Item Management'),
    (uuid_generate_v4(), 'items:list', 'List Items', 'Permission to list items', 'items', 'list', 'Item Management');

-- Invitation permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'invitations:create', 'Create Invitations', 'Permission to create invitations', 'invitations', 'create', 'Invitation Management'),
    (uuid_generate_v4(), 'invitations:read', 'View Invitations', 'Permission to view invitation details', 'invitations', 'read', 'Invitation Management'),
    (uuid_generate_v4(), 'invitations:delete', 'Delete Invitations', 'Permission to revoke invitations', 'invitations', 'delete', 'Invitation Management'),
    (uuid_generate_v4(), 'invitations:list', 'List Invitations', 'Permission to list invitations', 'invitations', 'list', 'Invitation Management');

-- Settings permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'settings:read', 'View Settings', 'Permission to view settings', 'settings', 'read', 'Settings'),
    (uuid_generate_v4(), 'settings:update', 'Update Settings', 'Permission to update settings', 'settings', 'update', 'Settings');

-- Reports permissions
INSERT INTO permissions (id, code, name, description, resource, action, category) VALUES
    (uuid_generate_v4(), 'reports:read', 'View Reports', 'Permission to view reports', 'reports', 'read', 'Reporting'),
    (uuid_generate_v4(), 'reports:list', 'List Reports', 'Permission to list reports', 'reports', 'list', 'Reporting');

-- Insert system roles

-- System Admin (platform level, not organization specific).
-- Historically called "super_admin"; renamed in migration 005.
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'system_admin', 'System Admin', 'Platform-level system administrator with full access', 'system', 0, false);

-- Base User (default role for all registered users outside org context)
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'base_user', 'Base User', 'Default role for registered users', 'system', 100, false);

-- Organization Admin
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'org_admin', 'Organization Admin', 'Full administrative access within an organization', 'system', 10, true);

-- Organization Manager
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'org_manager', 'Organization Manager', 'Can manage users and their roles within the organization', 'system', 20, true);

-- Seller
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'seller', 'Seller', 'Can create and manage auctions and items', 'system', 50, true);

-- Buyer
INSERT INTO roles (id, code, name, description, type, level, is_org_role) VALUES
    (uuid_generate_v4(), 'buyer', 'Buyer', 'Can view auctions and place bids', 'system', 60, true);

-- Assign all permissions to system_admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'system_admin';

-- Assign permissions to org_admin
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'org_admin'
AND p.code IN (
    'users:read', 'users:update', 'users:list', 'users:invite',
    'organizations:read', 'organizations:update',
    'roles:create', 'roles:read', 'roles:update', 'roles:delete', 'roles:list', 'roles:assign',
    'permissions:read', 'permissions:list',
    'auctions:create', 'auctions:read', 'auctions:update', 'auctions:delete', 'auctions:list', 'auctions:manage', 'auctions:approve',
    'bids:read', 'bids:list',
    'items:create', 'items:read', 'items:update', 'items:delete', 'items:list',
    'invitations:create', 'invitations:read', 'invitations:delete', 'invitations:list',
    'settings:read', 'settings:update',
    'reports:read', 'reports:list'
);

-- Assign permissions to org_manager
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'org_manager'
AND p.code IN (
    'users:read', 'users:update', 'users:list', 'users:invite',
    'organizations:read',
    'roles:read', 'roles:list', 'roles:assign',
    'permissions:read', 'permissions:list',
    'auctions:read', 'auctions:list',
    'bids:read', 'bids:list',
    'items:read', 'items:list',
    'invitations:create', 'invitations:read', 'invitations:delete', 'invitations:list',
    'reports:read', 'reports:list'
);

-- Assign permissions to seller
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'seller'
AND p.code IN (
    'auctions:create', 'auctions:read', 'auctions:update', 'auctions:list',
    'items:create', 'items:read', 'items:update', 'items:delete', 'items:list',
    'bids:read', 'bids:list'
);

-- Assign permissions to buyer
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'buyer'
AND p.code IN (
    'auctions:read', 'auctions:list',
    'items:read', 'items:list',
    'bids:create', 'bids:read', 'bids:list'
);

-- Assign minimal permissions to base_user
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r, permissions p
WHERE r.code = 'base_user'
AND p.code IN (
    'auctions:read', 'auctions:list',
    'items:read', 'items:list'
);
