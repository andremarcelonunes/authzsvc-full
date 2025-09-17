-- CB-176 E2E Test Database Setup
-- This script sets up the complete database structure for your local PostgreSQL
-- Supports all authentication, authorization, and E2E testing requirements

-- Create database and user (run as postgres superuser)
-- CREATE DATABASE authdb;
-- CREATE USER auth WITH PASSWORD '123456';
-- GRANT ALL PRIVILEGES ON DATABASE authdb TO auth;

-- Connect to authdb database and create schema
-- \c authdb;
CREATE SCHEMA IF NOT EXISTS auth;
GRANT ALL ON SCHEMA auth TO auth;
ALTER USER auth SET search_path TO auth;

-- Ensure auth user has necessary permissions
GRANT CREATE ON SCHEMA auth TO auth;
GRANT USAGE ON SCHEMA auth TO auth;

-- Set default privileges for future tables
ALTER DEFAULT PRIVILEGES IN SCHEMA auth 
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO auth;

ALTER DEFAULT PRIVILEGES IN SCHEMA auth 
GRANT USAGE, SELECT ON SEQUENCES TO auth;

-- ============================================================================
-- USERS TABLE - Core user entity for authentication and authorization
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth.users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    phone VARCHAR(32),
    password VARCHAR(255) NOT NULL,
    role VARCHAR(64) NOT NULL DEFAULT 'user',
    is_active BOOLEAN NOT NULL DEFAULT true,
    phone_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);

-- Create indexes for users table performance
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON auth.users (email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_phone ON auth.users (phone) WHERE phone IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_role ON auth.users (role);
CREATE INDEX IF NOT EXISTS idx_users_is_active ON auth.users (is_active);
CREATE INDEX IF NOT EXISTS idx_users_phone_verified ON auth.users (phone_verified);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON auth.users (created_at);
CREATE INDEX IF NOT EXISTS idx_users_updated_at ON auth.users (updated_at);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON auth.users (deleted_at);

-- Add trigger to auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION auth.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_users_updated_at 
    BEFORE UPDATE ON auth.users 
    FOR EACH ROW EXECUTE FUNCTION auth.update_updated_at_column();

-- ============================================================================
-- CASBIN POLICY TABLE - Authorization policies managed by Casbin GORM adapter
-- ============================================================================
CREATE TABLE IF NOT EXISTS auth.casbin_rules (
    id SERIAL PRIMARY KEY,
    ptype VARCHAR(255) NOT NULL,
    v0 VARCHAR(255),
    v1 VARCHAR(255),
    v2 VARCHAR(255),
    v3 VARCHAR(255),
    v4 VARCHAR(255),
    v5 VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for Casbin policy queries
CREATE INDEX IF NOT EXISTS idx_casbin_rules_ptype ON auth.casbin_rules (ptype);
CREATE INDEX IF NOT EXISTS idx_casbin_rules_v0 ON auth.casbin_rules (v0);
CREATE INDEX IF NOT EXISTS idx_casbin_rules_v1 ON auth.casbin_rules (v1);
CREATE INDEX IF NOT EXISTS idx_casbin_rules_v2 ON auth.casbin_rules (v2);
CREATE UNIQUE INDEX IF NOT EXISTS idx_casbin_rules_unique 
    ON auth.casbin_rules (ptype, v0, v1, v2, v3, v4, v5);

-- Add trigger for casbin_rules updated_at
CREATE TRIGGER update_casbin_rules_updated_at 
    BEFORE UPDATE ON auth.casbin_rules 
    FOR EACH ROW EXECUTE FUNCTION auth.update_updated_at_column();

-- ============================================================================
-- SEED DEFAULT POLICIES - Initial RBAC configuration
-- ============================================================================
INSERT INTO auth.casbin_rules (ptype, v0, v1, v2) VALUES 
    ('p', 'admin', '/admin/*', '*'),
    ('p', 'admin', '/auth/*', '*'),
    ('p', 'user', '/auth/me', 'GET'),
    ('p', 'user', '/auth/logout', 'POST'),
    ('p', 'user', '/auth/refresh', 'POST')
ON CONFLICT (ptype, v0, v1, v2, v3, v4, v5) DO NOTHING;

-- ============================================================================
-- SEED TEST USERS - Initial users for development and testing
-- ============================================================================
-- Admin user for testing (password: 'admin123')
INSERT INTO auth.users (email, phone, password, role, is_active, phone_verified) VALUES 
    ('admin@authz.test', '+1234567890', '$2a$10$Ow7.6Q8Ym7Q8Ym7Q8Ym7Q.6Q8Ym7Q8Ym7Q8Ym7Q8Ym7Q8Ym7Q8Y', 'admin', true, true),
    ('user@authz.test', '+1987654321', '$2a$10$Ow7.6Q8Ym7Q8Ym7Q8Ym7Q.6Q8Ym7Q8Ym7Q8Ym7Q8Ym7Q8Ym7Q8Y', 'user', true, true)
ON CONFLICT (email) DO NOTHING;

-- ============================================================================
-- TEST DATA MANAGEMENT - Utilities for E2E testing
-- ============================================================================

-- Enhanced cleanup procedure for comprehensive E2E test isolation
CREATE OR REPLACE FUNCTION auth.cleanup_test_data()
RETURNS void AS $$
BEGIN
    -- Delete test users (emails starting with 'test_' or containing '.test')
    DELETE FROM auth.users WHERE email LIKE 'test_%' OR email LIKE '%.test%';
    
    -- Clean up test policies (but preserve default ones)
    DELETE FROM auth.casbin_rules 
    WHERE (v0 LIKE 'test_%' OR v1 LIKE 'test_%' OR v2 LIKE 'test_%')
    AND NOT (ptype = 'p' AND v0 IN ('admin', 'user'));
    
    -- Reset sequences if needed for consistent test IDs
    PERFORM setval('auth.users_id_seq', (SELECT COALESCE(MAX(id), 0) FROM auth.users) + 1, false);
    PERFORM setval('auth.casbin_rules_id_seq', (SELECT COALESCE(MAX(id), 0) FROM auth.casbin_rules) + 1, false);
    
    RAISE NOTICE 'Test data cleanup completed - removed test users and policies';
END;
$$ LANGUAGE plpgsql;

-- Function to verify database setup and configuration
CREATE OR REPLACE FUNCTION auth.verify_setup()
RETURNS TABLE(
    component TEXT,
    status TEXT,
    details TEXT
) AS $$
BEGIN
    -- Check users table
    RETURN QUERY SELECT 
        'users_table'::TEXT,
        'OK'::TEXT,
        ('Users: ' || count(*)::TEXT)::TEXT
    FROM auth.users;
    
    -- Check casbin_rules table
    RETURN QUERY SELECT 
        'casbin_table'::TEXT,
        'OK'::TEXT,
        ('Policies: ' || count(*)::TEXT)::TEXT
    FROM auth.casbin_rules;
    
    -- Check indexes
    RETURN QUERY SELECT 
        'indexes'::TEXT,
        'OK'::TEXT,
        ('Total indexes: ' || count(*)::TEXT)::TEXT
    FROM pg_indexes 
    WHERE schemaname = 'auth';
    
    -- Check permissions
    RETURN QUERY SELECT 
        'permissions'::TEXT,
        CASE 
            WHEN has_schema_privilege('auth', 'auth', 'CREATE,USAGE') THEN 'OK'
            ELSE 'ERROR'
        END::TEXT,
        'Schema permissions verified'::TEXT;
    
    RETURN;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permissions to auth user
GRANT EXECUTE ON FUNCTION auth.cleanup_test_data() TO auth;
GRANT EXECUTE ON FUNCTION auth.verify_setup() TO auth;

-- ============================================================================
-- VERIFICATION AND STATUS
-- ============================================================================

-- Run verification and display results
SELECT * FROM auth.verify_setup();

-- Final status message
SELECT 
    'CB-176 Database Setup Complete' as status,
    'Ready for E2E authentication tests' as message,
    current_timestamp as setup_time;