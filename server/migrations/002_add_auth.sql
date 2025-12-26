-- Night Market Booking System
-- Migration: Add authentication columns to riders table

-- Add password_hash column for authentication
ALTER TABLE riders ADD COLUMN IF NOT EXISTS password_hash VARCHAR(255);

-- Add role column for authorization (rider or admin)
ALTER TABLE riders ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'rider' CHECK (role IN ('rider', 'admin'));

-- Create index on role for faster admin queries
CREATE INDEX IF NOT EXISTS idx_riders_role ON riders(role);

-- Insert a default admin user (password: admin123)
-- Note: In production, change this password immediately
-- This hash is for 'admin123' using bcrypt
INSERT INTO riders (rider_id, name, email, password_hash, role, is_verified)
VALUES (
  'ADMIN-001',
  'Admin User',
  'admin@nightmarket.com',
  '$2b$10$zG8LEjM1uFB9lltGTPqRsuogLy2.APd8Lp3AFM5gUe0GoOnx4gpDy',
  'admin',
  TRUE
) ON CONFLICT (email) DO UPDATE SET role = 'admin';

COMMENT ON COLUMN riders.password_hash IS 'Bcrypt hashed password for authentication';
COMMENT ON COLUMN riders.role IS 'User role: rider (default) or admin';
