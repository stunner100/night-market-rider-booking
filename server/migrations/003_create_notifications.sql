-- Night Market Booking System
-- Migration: Create notifications table

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
  id SERIAL PRIMARY KEY,
  rider_id VARCHAR(50) NOT NULL,
  type VARCHAR(50) NOT NULL,  -- booking_reminder, booking_confirmed, booking_cancelled, system_alert
  title VARCHAR(255) NOT NULL,
  message TEXT NOT NULL,
  booking_id VARCHAR(10),
  is_read BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_notifications_rider ON notifications(rider_id);
CREATE INDEX IF NOT EXISTS idx_notifications_unread ON notifications(rider_id, is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);

-- Add comments for documentation
COMMENT ON TABLE notifications IS 'In-app notifications for riders';
COMMENT ON COLUMN notifications.type IS 'Type of notification: booking_reminder, booking_confirmed, booking_cancelled, system_alert';
COMMENT ON COLUMN notifications.booking_id IS 'Optional reference to related booking';
