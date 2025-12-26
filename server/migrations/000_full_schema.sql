-- Night Market Booking System
-- Full Database Schema for Vercel Postgres
-- Run this SQL in your Vercel Postgres dashboard after creating the database

-- Create bookings table
CREATE TABLE IF NOT EXISTS bookings (
  id SERIAL PRIMARY KEY,
  booking_id VARCHAR(10) UNIQUE NOT NULL,
  rider_id VARCHAR(50) NOT NULL,
  rider_name VARCHAR(100) NOT NULL,
  rider_email VARCHAR(255) NOT NULL,
  booking_date DATE NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes IN (30, 45, 60, 90, 120, 180, 240)),
  zone VARCHAR(50) DEFAULT 'Main Campus',
  hourly_rate DECIMAL(10,2) DEFAULT 20.00,
  total_cost DECIMAL(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'confirmed' CHECK (status IN ('pending', 'confirmed', 'active', 'completed', 'cancelled')),
  vehicle_assignment VARCHAR(50),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for bookings
CREATE INDEX IF NOT EXISTS idx_bookings_date ON bookings(booking_date);
CREATE INDEX IF NOT EXISTS idx_bookings_rider ON bookings(rider_id);
CREATE INDEX IF NOT EXISTS idx_bookings_status ON bookings(status);
CREATE INDEX IF NOT EXISTS idx_bookings_zone_date ON bookings(zone, booking_date);

-- Create riders table
CREATE TABLE IF NOT EXISTS riders (
  id SERIAL PRIMARY KEY,
  rider_id VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  phone VARCHAR(20),
  avatar_url TEXT,
  password_hash VARCHAR(255),
  role VARCHAR(20) DEFAULT 'rider' CHECK (role IN ('rider', 'admin')),
  preferred_zone VARCHAR(50),
  is_verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for riders
CREATE INDEX IF NOT EXISTS idx_riders_email ON riders(email);
CREATE INDEX IF NOT EXISTS idx_riders_role ON riders(role);

-- Create zones table
CREATE TABLE IF NOT EXISTS zones (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  capacity INTEGER DEFAULT 1,
  is_active BOOLEAN DEFAULT TRUE
);

-- Insert default zones
INSERT INTO zones (name, description, capacity) VALUES
  ('Main Campus', 'Primary riding area with full facilities', 3),
  ('Zone A', 'Beginner-friendly enclosed area', 2),
  ('Zone B', 'Advanced training area', 2),
  ('Trail Circuit', 'Scenic trail riding path', 4)
ON CONFLICT (name) DO NOTHING;

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY,
  rider_id VARCHAR(50) NOT NULL,
  type VARCHAR(50) NOT NULL,
  title VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  booking_id VARCHAR(10),
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for notifications
CREATE INDEX IF NOT EXISTS idx_notifications_rider ON notifications(rider_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(rider_id, is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);

-- Create notification settings table
CREATE TABLE IF NOT EXISTS notification_settings (
  id SERIAL PRIMARY KEY,
  rider_id VARCHAR(50) UNIQUE NOT NULL,
  enable_all BOOLEAN DEFAULT TRUE,
  email_enabled BOOLEAN DEFAULT TRUE,
  sms_enabled BOOLEAN DEFAULT TRUE,
  in_app_enabled BOOLEAN DEFAULT TRUE,
  reminder_timing VARCHAR(20) DEFAULT '1_hour',
  confirmation_timing VARCHAR(20) DEFAULT 'immediately',
  cancellation_alerts BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_notification_settings_rider ON notification_settings(rider_id);

-- Insert default admin user (password: admin123)
-- Change this password immediately in production!
INSERT INTO riders (rider_id, name, email, password_hash, role, is_verified)
VALUES (
  'ADMIN-001',
  'Admin User',
  'admin@nightmarket.com',
  '$2b$10$zG8LEjM1uFB9lltGTPqRsuogLy2.APd8Lp3AFM5gUe0GoOnx4gpDy',
  'admin',
  TRUE
) ON CONFLICT (email) DO UPDATE SET role = 'admin';

-- Create function to update timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at
DROP TRIGGER IF EXISTS update_bookings_updated_at ON bookings;
CREATE TRIGGER update_bookings_updated_at
  BEFORE UPDATE ON bookings
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS update_riders_updated_at ON riders;
CREATE TRIGGER update_riders_updated_at
  BEFORE UPDATE ON riders
  FOR EACH ROW
  EXECUTE FUNCTION update_updated_at_column();
