-- Hapus tabel lama jika ada konflik (Hati-hati jika ada data penting)
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS otp_requests;

-- 1. TABEL USERS (Dengan fitur Brute-Force Lockout)
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email_norm TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    phone TEXT,
    password_hash TEXT,
    password_salt TEXT,
    password_iter INTEGER,
    password_algo TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    pw_fail_count INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER
);

-- 2. TABEL ROLES
CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

-- 3. TABEL USER_ROLES (Relasi Many-to-Many)
CREATE TABLE user_roles (
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, role_id)
);

-- 4. TABEL SESSIONS (Dengan IP/Device Binding)
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    ip_hash TEXT,
    ua_hash TEXT,
    role_snapshot TEXT,
    ip_prefix_hash TEXT,
    last_seen_at INTEGER,
    roles_json TEXT,
    session_version INTEGER NOT NULL DEFAULT 1,
    revoke_reason TEXT
);

-- 5. TABEL OTP_REQUESTS (Penyatuan sistem OTP & Step-up)
CREATE TABLE otp_requests (
    id TEXT PRIMARY KEY,
    purpose TEXT NOT NULL,
    identifier_hash TEXT NOT NULL,
    otp_hash TEXT NOT NULL,
    otp_salt TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER
);

-- Insert Default Roles
INSERT INTO roles (id, name, created_at) VALUES 
('role_superadmin', 'super_admin', strftime('%s','now')),
('role_admin', 'admin', strftime('%s','now')),
('role_staff', 'staff', strftime('%s','now')),
('role_client', 'client', strftime('%s','now')),
('role_talent', 'talent', strftime('%s','now'));
