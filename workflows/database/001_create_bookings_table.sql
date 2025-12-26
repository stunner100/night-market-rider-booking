-- Night Market Booking System
-- Migration: Create bookings table
-- Run this SQL in your PostgreSQL database

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
  duration_minutes INTEGER NOT NULL CHECK (duration_minutes IN (30, 45, 60, 90)),
  zone VARCHAR(50) DEFAULT 'Main Paddock',
  hourly_rate DECIMAL(10,2) DEFAULT 20.00,
  total_cost DECIMAL(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'confirmed' CHECK (status IN ('pending', 'confirmed', 'active', 'completed', 'cancelled')),
  vehicle_assignment VARCHAR(50),
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for common queries
CREATE INDEX idx_bookings_date ON bookings(booking_date);
CREATE INDEX idx_bookings_rider ON bookings(rider_id);
CREATE INDEX idx_bookings_status ON bookings(status);
CREATE INDEX idx_bookings_zone_date ON bookings(zone, booking_date);

-- Create riders table for user management
CREATE TABLE IF NOT EXISTS riders (
  id SERIAL PRIMARY KEY,
  rider_id VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(100) NOT NULL,
  email VARCHAR(255) UNIQUE NOT NULL,
  phone VARCHAR(20),
  avatar_url TEXT,
  is_verified BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_riders_email ON riders(email);

-- Create zones table for riding areas
CREATE TABLE IF NOT EXISTS zones (
  id SERIAL PRIMARY KEY,
  name VARCHAR(50) UNIQUE NOT NULL,
  description TEXT,
  capacity INTEGER DEFAULT 1,
  is_active BOOLEAN DEFAULT TRUE
);

-- Insert default zones
INSERT INTO zones (name, description, capacity) VALUES
  ('Main Paddock', 'Primary riding area with full facilities', 3),
  ('Zone A', 'Beginner-friendly enclosed area', 2),
  ('Zone B', 'Advanced training area', 2),
  ('Trail Circuit', 'Scenic trail riding path', 4)
ON CONFLICT (name) DO NOTHING;

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

-- Create view for upcoming bookings (admin dashboard)
CREATE OR REPLACE VIEW upcoming_bookings AS
SELECT
  b.booking_id,
  b.rider_name,
  b.rider_email,
  b.booking_date,
  b.start_time,
  b.end_time,
  b.duration_minutes,
  b.zone,
  b.total_cost,
  b.status,
  b.vehicle_assignment,
  b.created_at
FROM bookings b
WHERE b.booking_date >= CURRENT_DATE
  AND b.status NOT IN ('cancelled', 'completed')
ORDER BY b.booking_date, b.start_time;

-- Create view for daily revenue stats
CREATE OR REPLACE VIEW daily_revenue AS
SELECT
  booking_date,
  COUNT(*) as total_bookings,
  SUM(total_cost) as revenue,
  COUNT(DISTINCT rider_id) as unique_riders
FROM bookings
WHERE status IN ('confirmed', 'active', 'completed')
GROUP BY booking_date
ORDER BY booking_date DESC;

COMMENT ON TABLE bookings IS 'Stores all rider booking records for Night Market';
COMMENT ON TABLE riders IS 'Registered riders in the Night Market system';
COMMENT ON TABLE zones IS 'Available riding zones/areas';
