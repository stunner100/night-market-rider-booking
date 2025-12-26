-- Night Market Booking System
-- Migration: Create notification settings table

-- Create notification settings table
CREATE TABLE IF NOT EXISTS notification_settings (
  id SERIAL PRIMARY KEY,
  rider_id VARCHAR(50) UNIQUE NOT NULL,
  enable_all BOOLEAN DEFAULT TRUE,
  email_enabled BOOLEAN DEFAULT TRUE,
  sms_enabled BOOLEAN DEFAULT TRUE,
  in_app_enabled BOOLEAN DEFAULT TRUE,
  reminder_timing VARCHAR(20) DEFAULT '1_hour',  -- 24_hours, 1_hour, 15_minutes, never
  confirmation_timing VARCHAR(20) DEFAULT 'immediately',  -- immediately, daily_digest, never
  cancellation_alerts BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create index for efficient lookup
CREATE INDEX IF NOT EXISTS idx_notification_settings_rider ON notification_settings(rider_id);

-- Add comments for documentation
COMMENT ON TABLE notification_settings IS 'User preferences for notification delivery';
COMMENT ON COLUMN notification_settings.reminder_timing IS 'When to send ride reminders: 24_hours, 1_hour, 15_minutes, never';
COMMENT ON COLUMN notification_settings.confirmation_timing IS 'When to send booking confirmations: immediately, daily_digest, never';
