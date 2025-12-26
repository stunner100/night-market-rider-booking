import express from 'express';
import cors from 'cors';
import pg from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import OpenAI from 'openai';

// Initialize Qwen client via OpenAI-compatible API
const openai = new OpenAI({
  apiKey: process.env.DASHSCOPE_API_KEY,
  baseURL: 'https://dashscope-intl.aliyuncs.com/compatible-mode/v1'
});
// JWT Configuration
const JWT_SECRET = process.env.JWT_SECRET || 'night-market-secret-key-change-in-production';
const JWT_EXPIRES_IN = '7d';

const app = express();

// Booking capacity configuration
const DAILY_BIKE_LIMIT = 20; // Maximum bookings per day (first 20 can book any slot)

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper functions
function generateBookingId() {
  const num = Math.floor(1000 + Math.random() * 9000);
  return `BK-${num}`;
}

function generateRiderId() {
  const num = Math.floor(10000 + Math.random() * 90000);
  return `RDR-${num}`;
}

function calculateEndTime(startTime, durationMinutes) {
  const [hours, minutes] = startTime.split(':').map(Number);
  const totalMinutes = hours * 60 + minutes + durationMinutes;
  const endHours = Math.floor(totalMinutes / 60) % 24;
  const endMins = totalMinutes % 60;
  return `${String(endHours).padStart(2, '0')}:${String(endMins).padStart(2, '0')}`;
}

function calculateCost(durationMinutes, hourlyRate = 20) {
  return (durationMinutes / 60) * hourlyRate;
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'UNAUTHORIZED',
      message: 'Access token required'
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        error: 'FORBIDDEN',
        message: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      error: 'FORBIDDEN',
      message: 'Admin access required'
    });
  }
  next();
}

// Validation middleware
function validateBookingData(req, res, next) {
  const { rider_id, rider_name, rider_email, booking_date, start_time, duration_minutes } = req.body;
  const errors = [];

  if (!rider_id) errors.push('rider_id is required');
  if (!rider_name) errors.push('rider_name is required');
  if (!rider_email) errors.push('rider_email is required');
  if (!booking_date) errors.push('booking_date is required');
  if (!start_time) errors.push('start_time is required');
  if (!duration_minutes) errors.push('duration_minutes is required');

  if (booking_date && !/^\d{4}-\d{2}-\d{2}$/.test(booking_date)) {
    errors.push('booking_date must be in YYYY-MM-DD format');
  }

  // Prevent booking past dates
  if (booking_date) {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const bookingDateObj = new Date(booking_date + 'T00:00:00');
    if (bookingDateObj < today) {
      errors.push('Cannot book dates in the past');
    }
  }

  if (start_time && !/^\d{2}:\d{2}$/.test(start_time)) {
    errors.push('start_time must be in HH:MM format');
  }

  // Validate duration (allow any reasonable duration between 15 minutes and 8 hours)
  const durationNum = Number(duration_minutes);
  if (duration_minutes && (isNaN(durationNum) || durationNum < 15 || durationNum > 480)) {
    errors.push('duration_minutes must be between 15 and 480 minutes');
  }

  if (rider_email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rider_email)) {
    errors.push('rider_email must be a valid email address');
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Missing or invalid required fields',
      errors
    });
  }

  next();
}

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// =====================
// AUTH ROUTES
// =====================

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, phone } = req.body;

    if (!name || !phone) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Name and phone number are required'
      });
    }

    // Check if phone number already exists
    const existingUser = await pool.query(
      'SELECT id FROM riders WHERE phone = $1',
      [phone]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'PHONE_EXISTS',
        message: 'An account with this phone number already exists'
      });
    }

    let riderId;
    let isUnique = false;
    while (!isUnique) {
      riderId = generateRiderId();
      const checkResult = await pool.query(
        'SELECT 1 FROM riders WHERE rider_id = $1',
        [riderId]
      );
      isUnique = checkResult.rows.length === 0;
    }

    const result = await pool.query(
      `INSERT INTO riders (rider_id, name, phone, role, is_verified)
       VALUES ($1, $2, $3, 'rider', FALSE)
       RETURNING rider_id, name, phone, role, is_verified, created_at`,
      [riderId, name, phone]
    );

    const rider = result.rows[0];

    const token = jwt.sign(
      { rider_id: rider.rider_id, phone: rider.phone, role: rider.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token,
      user: {
        rider_id: rider.rider_id,
        name: rider.name,
        phone: rider.phone,
        role: rider.role,
        is_verified: rider.is_verified
      }
    });

  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred during registration'
    });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { name, phone } = req.body;

    if (!name || !phone) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Name and phone number are required'
      });
    }

    // Find user by phone number
    const result = await pool.query(
      'SELECT * FROM riders WHERE phone = $1',
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'No account found with this phone number'
      });
    }

    const rider = result.rows[0];

    // Verify name matches (case-insensitive)
    if (rider.name.toLowerCase() !== name.toLowerCase()) {
      return res.status(401).json({
        success: false,
        error: 'INVALID_CREDENTIALS',
        message: 'Name does not match the account'
      });
    }

    const token = jwt.sign(
      { rider_id: rider.rider_id, phone: rider.phone, role: rider.role || 'rider' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        rider_id: rider.rider_id,
        name: rider.name,
        phone: rider.phone,
        role: rider.role || 'rider',
        is_verified: rider.is_verified,
        avatar_url: rider.avatar_url
      }
    });

  } catch (error) {
    console.error('Error logging in:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred during login'
    });
  }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT rider_id, name, email, phone, role, is_verified, avatar_url, created_at FROM riders WHERE rider_id = $1',
      [req.user.rider_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: 'User not found'
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });

  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while fetching user data'
    });
  }
});



// =====================
// BOOKING ROUTES
// =====================

// Create booking
app.post('/api/bookings', validateBookingData, async (req, res) => {
  try {
    const {
      rider_id,
      rider_name,
      rider_email,
      booking_date,
      start_time,
      duration_minutes,
      zone = 'Main Campus'
    } = req.body;

    const end_time = calculateEndTime(start_time, duration_minutes);
    const hourly_rate = 20.00;
    const total_cost = calculateCost(duration_minutes, hourly_rate);

    // Step 1: Count total bookings for the day (20-bike capacity system)
    const dailyCountResult = await pool.query(
      `SELECT COUNT(*) as daily_count FROM bookings WHERE booking_date = $1 AND status != 'cancelled'`,
      [booking_date]
    );
    const dailyBookingCount = parseInt(dailyCountResult.rows[0].daily_count);

    // Step 2: Check availability based on daily capacity
    // First 20 bookings can choose any slot; after that, only empty slots are available
    if (dailyBookingCount >= DAILY_BIKE_LIMIT) {
      const slotResult = await pool.query(
        `SELECT COUNT(*) as slot_count FROM bookings
         WHERE booking_date = $1 AND status != 'cancelled' AND start_time < $3 AND end_time > $2`,
        [booking_date, start_time, end_time]
      );

      if (parseInt(slotResult.rows[0].slot_count) > 0) {
        return res.status(409).json({
          success: false,
          error: 'SLOT_UNAVAILABLE',
          message: 'Daily capacity reached (20 bikes). Only completely empty time slots are available.',
          daily_count: dailyBookingCount,
          daily_limit: DAILY_BIKE_LIMIT
        });
      }
    }
    // If dailyBookingCount < DAILY_BIKE_LIMIT, any slot is allowed (no conflict check needed)

    let booking_id;
    let isUnique = false;
    while (!isUnique) {
      booking_id = generateBookingId();
      const checkResult = await pool.query('SELECT 1 FROM bookings WHERE booking_id = $1', [booking_id]);
      isUnique = checkResult.rows.length === 0;
    }

    const insertResult = await pool.query(
      `INSERT INTO bookings (booking_id, rider_id, rider_name, rider_email, booking_date, start_time, end_time, duration_minutes, zone, hourly_rate, total_cost, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'confirmed') RETURNING *`,
      [booking_id, rider_id, rider_name, rider_email, booking_date, start_time, end_time, duration_minutes, zone, hourly_rate, total_cost]
    );

    res.status(201).json({
      success: true,
      message: 'Booking created successfully',
      booking: insertResult.rows[0]
    });

  } catch (error) {
    console.error('Error creating booking:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while creating the booking.'
    });
  }
});

// Get bookings
app.get('/api/bookings', async (req, res) => {
  try {
    const { date, rider_id, zone, status } = req.query;

    let query = 'SELECT * FROM bookings WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (date) { query += ` AND booking_date = $${paramIndex++}`; params.push(date); }
    if (rider_id) { query += ` AND rider_id = $${paramIndex++}`; params.push(rider_id); }
    if (zone) { query += ` AND zone = $${paramIndex++}`; params.push(zone); }
    if (status) { query += ` AND status = $${paramIndex++}`; params.push(status); }

    query += ' ORDER BY booking_date DESC, start_time ASC';

    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rows.length, bookings: result.rows });

  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'An error occurred while fetching bookings.' });
  }
});

// Get weekly bookings (batch endpoint for performance)
// IMPORTANT: This must come BEFORE the /:bookingId route to avoid route conflicts
app.get('/api/bookings/week', async (req, res) => {
  try {
    const { start_date } = req.query;

    if (!start_date) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'start_date query parameter is required (YYYY-MM-DD)'
      });
    }

    // Validate date format
    if (!/^\d{4}-\d{2}-\d{2}$/.test(start_date)) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'start_date must be in YYYY-MM-DD format'
      });
    }

    // Calculate week end date (6 days after start)
    const startDate = new Date(start_date + 'T00:00:00');
    const endDate = new Date(startDate);
    endDate.setDate(endDate.getDate() + 6);
    const end_date = endDate.toISOString().split('T')[0];

    // Single query to get all bookings for the week
    const bookingsResult = await pool.query(
      `SELECT booking_id, rider_id, rider_name, booking_date, start_time, end_time, zone, status
       FROM bookings 
       WHERE booking_date >= $1 AND booking_date <= $2 AND status != 'cancelled'
       ORDER BY booking_date, start_time`,
      [start_date, end_date]
    );

    // Single query to get daily counts for the week
    const countsResult = await pool.query(
      `SELECT booking_date, COUNT(*) as daily_count
       FROM bookings 
       WHERE booking_date >= $1 AND booking_date <= $2 AND status != 'cancelled'
       GROUP BY booking_date`,
      [start_date, end_date]
    );

    // Build a map of daily counts
    const dailyCounts = {};
    countsResult.rows.forEach(row => {
      dailyCounts[row.booking_date.toISOString().split('T')[0]] = parseInt(row.daily_count);
    });

    // Group bookings by date
    const bookingsByDate = {};
    bookingsResult.rows.forEach(booking => {
      const dateStr = booking.booking_date.toISOString().split('T')[0];
      if (!bookingsByDate[dateStr]) {
        bookingsByDate[dateStr] = [];
      }
      bookingsByDate[dateStr].push({
        booking_id: booking.booking_id,
        rider_id: booking.rider_id,
        rider_name: booking.rider_name,
        start_time: booking.start_time,
        end_time: booking.end_time,
        zone: booking.zone
      });
    });

    // Build response for each day of the week
    const days = [];
    for (let i = 0; i < 7; i++) {
      const currentDate = new Date(startDate);
      currentDate.setDate(startDate.getDate() + i);
      const dateStr = currentDate.toISOString().split('T')[0];
      const dailyCount = dailyCounts[dateStr] || 0;

      days.push({
        date: dateStr,
        daily_count: dailyCount,
        is_early_bird: dailyCount < DAILY_BIKE_LIMIT,
        bookings: bookingsByDate[dateStr] || []
      });
    }

    // Set cache header (1 minute)
    res.set('Cache-Control', 'public, max-age=60');

    res.json({
      success: true,
      week_start: start_date,
      week_end: end_date,
      daily_limit: DAILY_BIKE_LIMIT,
      days
    });

  } catch (error) {
    console.error('Error fetching weekly bookings:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while fetching weekly bookings.'
    });
  }
});

// Get single booking
app.get('/api/bookings/:bookingId', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM bookings WHERE booking_id = $1', [req.params.bookingId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'Booking not found' });
    }
    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'An error occurred.' });
  }
});

// Cancel booking
app.patch('/api/bookings/:bookingId/cancel', async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE bookings SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE booking_id = $1 AND status != 'cancelled' RETURNING *`,
      [req.params.bookingId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'Booking not found or already cancelled' });
    }
    res.json({ success: true, message: 'Booking cancelled successfully', booking: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'An error occurred.' });
  }
});

// Reschedule booking
app.patch('/api/bookings/:bookingId/reschedule', async (req, res) => {
  try {
    const { bookingId } = req.params;
    const { booking_date, start_time, duration_minutes } = req.body;

    if (!booking_date || !start_time) {
      return res.status(400).json({ success: false, error: 'VALIDATION_ERROR', message: 'booking_date and start_time are required' });
    }

    const existingBooking = await pool.query('SELECT * FROM bookings WHERE booking_id = $1', [bookingId]);
    if (existingBooking.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'Booking not found' });
    }

    const booking = existingBooking.rows[0];
    if (booking.status === 'cancelled' || booking.status === 'completed') {
      return res.status(400).json({ success: false, error: 'INVALID_STATUS', message: 'Cannot reschedule cancelled or completed bookings' });
    }

    const newDuration = duration_minutes || booking.duration_minutes;
    const end_time = calculateEndTime(start_time, newDuration);
    const total_cost = calculateCost(newDuration, booking.hourly_rate);

    // Check conflicts
    const conflictResult = await pool.query(
      `SELECT booking_id FROM bookings WHERE booking_date = $1 AND zone = $2 AND status != 'cancelled' AND booking_id != $3
       AND ((start_time <= $4 AND end_time > $4) OR (start_time < $5 AND end_time >= $5) OR (start_time >= $4 AND end_time <= $5))`,
      [booking_date, booking.zone, bookingId, start_time, end_time]
    );

    if (conflictResult.rows.length > 0) {
      return res.status(409).json({ success: false, error: 'SLOT_UNAVAILABLE', message: 'Time slot not available' });
    }

    const updateResult = await pool.query(
      `UPDATE bookings SET booking_date = $1, start_time = $2, end_time = $3, duration_minutes = $4, total_cost = $5, updated_at = CURRENT_TIMESTAMP WHERE booking_id = $6 RETURNING *`,
      [booking_date, start_time, end_time, newDuration, total_cost, bookingId]
    );

    res.json({ success: true, message: 'Booking rescheduled successfully', booking: updateResult.rows[0] });
  } catch (error) {
    console.error('Error rescheduling:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'An error occurred.' });
  }
});

// Get availability
app.get('/api/availability', async (req, res) => {
  try {
    const { date, zone = 'Main Campus' } = req.query;
    if (!date) {
      return res.status(400).json({ success: false, error: 'VALIDATION_ERROR', message: 'date is required' });
    }

    // Count total daily bookings for 20-bike capacity system
    const dailyCountResult = await pool.query(
      `SELECT COUNT(*) as daily_count FROM bookings WHERE booking_date = $1 AND status != 'cancelled'`,
      [date]
    );
    const dailyCount = parseInt(dailyCountResult.rows[0].daily_count);
    const isEarlyBird = dailyCount < DAILY_BIKE_LIMIT;

    const result = await pool.query(
      `SELECT start_time, end_time, zone, rider_name FROM bookings WHERE booking_date = $1 AND status != 'cancelled' ORDER BY start_time`,
      [date]
    );

    const allSlots = [];
    for (let hour = 8; hour < 22; hour++) {
      allSlots.push(`${String(hour).padStart(2, '0')}:00`);
      allSlots.push(`${String(hour).padStart(2, '0')}:30`);
    }

    const bookedSlots = result.rows.map(b => ({ start: b.start_time.slice(0, 5), end: b.end_time.slice(0, 5), zone: b.zone }));
    const availability = allSlots.map(slot => {
      const overlapping = bookedSlots.filter(booked => slot >= booked.start && slot < booked.end);
      const hasBookings = overlapping.length > 0;
      return { time: slot, available: isEarlyBird || !hasBookings, booking_count: overlapping.length, has_bookings: hasBookings };
    });

    res.json({
      success: true,
      date,
      zone,
      daily_count: dailyCount,
      daily_limit: DAILY_BIKE_LIMIT,
      remaining_early_bird_slots: Math.max(0, DAILY_BIKE_LIMIT - dailyCount),
      is_early_bird: isEarlyBird,
      slots: availability
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'An error occurred.' });
  }
});

// =====================
// NOTIFICATIONS
// =====================

app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const result = await pool.query(
      'SELECT * FROM notifications WHERE rider_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [req.user.rider_id, parseInt(limit), parseInt(offset)]
    );
    res.json({ success: true, count: result.rows.length, notifications: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch notifications.' });
  }
});

app.get('/api/notifications/count', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM notifications WHERE rider_id = $1 AND is_read = FALSE', [req.user.rider_id]);
    res.json({ success: true, unread_count: parseInt(result.rows[0].count) });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to count notifications.' });
  }
});

app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE notifications SET is_read = TRUE WHERE id = $1 AND rider_id = $2 RETURNING *`,
      [req.params.id, req.user.rider_id]
    );
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'NOT_FOUND' });
    res.json({ success: true, notification: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `UPDATE notifications SET is_read = TRUE WHERE rider_id = $1 AND is_read = FALSE`,
      [req.user.rider_id]
    );
    res.json({ success: true, updated_count: result.rowCount });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// =====================
// NOTIFICATION SETTINGS
// =====================

app.get('/api/notification-settings', authenticateToken, async (req, res) => {
  try {
    let result = await pool.query('SELECT * FROM notification_settings WHERE rider_id = $1', [req.user.rider_id]);
    if (result.rows.length === 0) {
      result = await pool.query(`INSERT INTO notification_settings (rider_id) VALUES ($1) RETURNING *`, [req.user.rider_id]);
    }
    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.put('/api/notification-settings', authenticateToken, async (req, res) => {
  try {
    const { enable_all, email_enabled, sms_enabled, in_app_enabled, reminder_timing, confirmation_timing, cancellation_alerts } = req.body;
    const result = await pool.query(
      `INSERT INTO notification_settings (rider_id, enable_all, email_enabled, sms_enabled, in_app_enabled, reminder_timing, confirmation_timing, cancellation_alerts)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       ON CONFLICT (rider_id) DO UPDATE SET
       enable_all = COALESCE($2, notification_settings.enable_all),
       email_enabled = COALESCE($3, notification_settings.email_enabled),
       sms_enabled = COALESCE($4, notification_settings.sms_enabled),
       in_app_enabled = COALESCE($5, notification_settings.in_app_enabled),
       reminder_timing = COALESCE($6, notification_settings.reminder_timing),
       confirmation_timing = COALESCE($7, notification_settings.confirmation_timing),
       cancellation_alerts = COALESCE($8, notification_settings.cancellation_alerts),
       updated_at = CURRENT_TIMESTAMP
       RETURNING *`,
      [req.user.rider_id, enable_all, email_enabled, sms_enabled, in_app_enabled, reminder_timing, confirmation_timing, cancellation_alerts]
    );
    res.json({ success: true, settings: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// =====================
// PROFILE
// =====================

app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, preferred_zone } = req.body;
    const result = await pool.query(
      `UPDATE riders SET name = COALESCE($1, name), phone = $2, preferred_zone = $3, updated_at = CURRENT_TIMESTAMP
       WHERE rider_id = $4 RETURNING rider_id, name, email, phone, preferred_zone, role, avatar_url`,
      [name, phone, preferred_zone, req.user.rider_id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND' });
    }
    res.json({ success: true, user: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// =====================
// ADMIN ROUTES
// =====================

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    const [activeResult, bookingsTodayResult, pendingResult, revenueResult] = await Promise.all([
      pool.query(`SELECT COUNT(DISTINCT rider_id) as count FROM bookings WHERE booking_date = $1 AND status = 'confirmed'`, [today]),
      pool.query(`SELECT COUNT(*) as count FROM bookings WHERE booking_date = $1`, [today]),
      pool.query(`SELECT COUNT(*) as count FROM bookings WHERE status = 'pending'`),
      pool.query(`SELECT COALESCE(SUM(total_cost), 0) as total FROM bookings WHERE booking_date = $1 AND status IN ('confirmed', 'completed')`, [today])
    ]);
    res.json({
      success: true,
      stats: {
        active_riders: parseInt(activeResult.rows[0].count),
        bookings_today: parseInt(bookingsTodayResult.rows[0].count),
        pending: parseInt(pendingResult.rows[0].count),
        revenue_today: parseFloat(revenueResult.rows[0].total)
      }
    });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.get('/api/admin/bookings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status, search, limit = 50, offset = 0 } = req.query;
    let query = 'SELECT * FROM bookings WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (status && status !== 'all') { query += ` AND status = $${paramIndex++}`; params.push(status); }
    if (search) { query += ` AND (booking_id ILIKE $${paramIndex} OR rider_name ILIKE $${paramIndex})`; params.push(`%${search}%`); paramIndex++; }
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(parseInt(limit), parseInt(offset));

    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rows.length, bookings: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.patch('/api/admin/bookings/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['confirmed', 'pending', 'cancelled', 'completed'].includes(status)) {
      return res.status(400).json({ success: false, error: 'VALIDATION_ERROR', message: 'Invalid status' });
    }
    const result = await pool.query(
      `UPDATE bookings SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE booking_id = $2 RETURNING *`,
      [status, req.params.id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND' });
    }
    res.json({ success: true, booking: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.get('/api/admin/riders/recent', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT rider_id, name, email, avatar_url, created_at FROM riders WHERE role = 'rider' ORDER BY created_at DESC LIMIT $1`,
      [parseInt(req.query.limit || 10)]
    );
    res.json({ success: true, riders: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

app.delete('/api/admin/bookings/clear-all', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM bookings RETURNING booking_id');
    res.json({ success: true, deleted_count: result.rowCount });
  } catch (error) {
    res.status(500).json({ success: false, error: 'SERVER_ERROR' });
  }
});

// =====================
// AI ASSISTANT ROUTES
// =====================

const CHATBOT_SYSTEM_PROMPT = `You are the Night Market AI Assistant, a helpful booking assistant for a bike riding service at night markets.

Your capabilities:
1. Help users book bike rides (you have access to booking functions)
2. Check availability for specific dates and times
3. Cancel or reschedule existing bookings
4. Answer questions about the service
5. Provide recommendations for optimal booking times

Service Details:
- Operating hours: 8:00 AM to 10:00 PM daily
- Zones available: Main Campus, Diaspora, Night Market, Pent & Beyond
- Pricing: $20 per hour
- Duration options: 30, 45, 60, 90, 120, 180, 240 minutes
- Daily capacity: 20 bikes (first 20 bookings get priority for any slot)

Guidelines:
- Be friendly, concise, and helpful
- When users want to book, ask for: date, time, duration, and zone (if not specified)
- Confirm details before making bookings
- Suggest alternatives if requested slot is unavailable
- Use 24-hour time format internally but display 12-hour format to users
- Always confirm the user's rider_id before making changes

Current date and time will be provided in each request.`;

const BOOKING_FUNCTIONS = [
  {
    type: "function",
    function: {
      name: "check_availability",
      description: "Check available time slots for a specific date",
      parameters: {
        type: "object",
        properties: {
          date: { type: "string", description: "The date to check in YYYY-MM-DD format" },
          zone: { type: "string", description: "The riding zone (optional)", enum: ["Main Campus", "Diaspora", "Night Market", "Pent & Beyond"] }
        },
        required: ["date"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "create_booking",
      description: "Create a new bike booking for the user",
      parameters: {
        type: "object",
        properties: {
          booking_date: { type: "string", description: "The booking date in YYYY-MM-DD format" },
          start_time: { type: "string", description: "The start time in HH:MM format (24-hour)" },
          duration_minutes: { type: "number", description: "Duration in minutes (30, 45, 60, 90, 120, 180, or 240)" },
          zone: { type: "string", description: "The riding zone", enum: ["Main Campus", "Diaspora", "Night Market", "Pent & Beyond"] }
        },
        required: ["booking_date", "start_time", "duration_minutes"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_user_bookings",
      description: "Get the user's upcoming and recent bookings",
      parameters: {
        type: "object",
        properties: {
          status: { type: "string", description: "Filter by booking status", enum: ["upcoming", "all", "cancelled", "completed"] }
        },
        required: []
      }
    }
  },
  {
    type: "function",
    function: {
      name: "cancel_booking",
      description: "Cancel an existing booking",
      parameters: {
        type: "object",
        properties: {
          booking_id: { type: "string", description: "The booking ID to cancel (e.g., BK-1234)" }
        },
        required: ["booking_id"]
      }
    }
  }
];

async function executeChatFunction(functionName, args, userContext) {
  const today = new Date().toISOString().split('T')[0];

  switch (functionName) {
    case 'check_availability': {
      const date = args.date || today;
      const zone = args.zone || 'Main Campus';

      const dailyCountResult = await pool.query(
        `SELECT COUNT(*) as daily_count FROM bookings WHERE booking_date = $1 AND status != 'cancelled'`,
        [date]
      );
      const dailyCount = parseInt(dailyCountResult.rows[0].daily_count);
      const isEarlyBird = dailyCount < DAILY_BIKE_LIMIT;

      const result = await pool.query(
        `SELECT start_time, end_time, zone FROM bookings WHERE booking_date = $1 AND status != 'cancelled' ORDER BY start_time`,
        [date]
      );

      const bookedSlots = result.rows.map(b => ({
        start: b.start_time.slice(0, 5),
        end: b.end_time.slice(0, 5),
        zone: b.zone
      }));

      const allSlots = [];
      for (let hour = 8; hour < 22; hour++) {
        const time = `${String(hour).padStart(2, '0')}:00`;
        const hasBooking = bookedSlots.some(b => time >= b.start && time < b.end);
        if (isEarlyBird || !hasBooking) {
          allSlots.push(time);
        }
      }

      return {
        date,
        zone,
        available_slots: allSlots,
        total_bookings: dailyCount,
        daily_limit: DAILY_BIKE_LIMIT,
        is_early_bird: isEarlyBird,
        remaining_spots: Math.max(0, DAILY_BIKE_LIMIT - dailyCount)
      };
    }

    case 'create_booking': {
      const { booking_date, start_time, duration_minutes, zone = 'Main Campus' } = args;

      const [hours, minutes] = start_time.split(':').map(Number);
      const totalMinutes = hours * 60 + minutes + duration_minutes;
      const endHours = Math.floor(totalMinutes / 60) % 24;
      const endMins = totalMinutes % 60;
      const end_time = `${String(endHours).padStart(2, '0')}:${String(endMins).padStart(2, '0')}`;

      const hourly_rate = 20.00;
      const total_cost = (duration_minutes / 60) * hourly_rate;

      const dailyCountResult = await pool.query(
        `SELECT COUNT(*) as daily_count FROM bookings WHERE booking_date = $1 AND status != 'cancelled'`,
        [booking_date]
      );
      const dailyCount = parseInt(dailyCountResult.rows[0].daily_count);

      if (dailyCount >= DAILY_BIKE_LIMIT) {
        const slotResult = await pool.query(
          `SELECT COUNT(*) as slot_count FROM bookings WHERE booking_date = $1 AND status != 'cancelled' AND start_time < $3 AND end_time > $2`,
          [booking_date, start_time, end_time]
        );
        if (parseInt(slotResult.rows[0].slot_count) > 0) {
          return { success: false, error: 'SLOT_UNAVAILABLE', message: 'This time slot is not available. Daily capacity reached.' };
        }
      }

      let booking_id;
      let isUnique = false;
      while (!isUnique) {
        booking_id = `BK-${Math.floor(1000 + Math.random() * 9000)}`;
        const checkResult = await pool.query('SELECT 1 FROM bookings WHERE booking_id = $1', [booking_id]);
        isUnique = checkResult.rows.length === 0;
      }

      const insertResult = await pool.query(
        `INSERT INTO bookings (booking_id, rider_id, rider_name, rider_email, booking_date, start_time, end_time, duration_minutes, zone, hourly_rate, total_cost, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, 'confirmed') RETURNING *`,
        [booking_id, userContext.rider_id, userContext.rider_name, userContext.rider_email, booking_date, start_time, end_time, duration_minutes, zone, hourly_rate, total_cost]
      );

      return {
        success: true,
        message: 'Booking created successfully!',
        booking: insertResult.rows[0]
      };
    }

    case 'get_user_bookings': {
      const status = args.status || 'upcoming';
      let query = 'SELECT * FROM bookings WHERE rider_id = $1';
      const params = [userContext.rider_id];

      if (status === 'upcoming') {
        query += ` AND booking_date >= $2 AND status IN ('confirmed', 'pending')`;
        params.push(today);
      } else if (status === 'cancelled') {
        query += ` AND status = 'cancelled'`;
      } else if (status === 'completed') {
        query += ` AND status = 'completed'`;
      }

      query += ' ORDER BY booking_date, start_time LIMIT 10';

      const result = await pool.query(query, params);
      return { bookings: result.rows, count: result.rows.length };
    }

    case 'cancel_booking': {
      const { booking_id } = args;

      const result = await pool.query(
        `UPDATE bookings SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP 
         WHERE booking_id = $1 AND rider_id = $2 AND status != 'cancelled' RETURNING *`,
        [booking_id, userContext.rider_id]
      );

      if (result.rows.length === 0) {
        return { success: false, error: 'NOT_FOUND', message: 'Booking not found or already cancelled' };
      }

      return { success: true, message: 'Booking cancelled successfully', booking: result.rows[0] };
    }

    default:
      return { error: 'Unknown function', function: functionName };
  }
}

// AI Chat endpoint
app.post('/api/ai/chat', authenticateToken, async (req, res) => {
  try {
    const { messages } = req.body;

    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Messages array is required'
      });
    }

    // Get full user context
    const userResult = await pool.query(
      'SELECT rider_id, name, email, phone FROM riders WHERE rider_id = $1',
      [req.user.rider_id]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'User not found' });
    }

    const userContext = {
      rider_id: userResult.rows[0].rider_id,
      rider_name: userResult.rows[0].name,
      rider_email: userResult.rows[0].email || `${userResult.rows[0].rider_id}@rider.nightmarket.local`
    };

    const currentTime = new Date().toISOString();
    const systemMessage = {
      role: "system",
      content: `${CHATBOT_SYSTEM_PROMPT}

Current Context:
- Current date/time: ${currentTime}
- User: ${userContext.rider_name} (ID: ${userContext.rider_id})
- User email: ${userContext.rider_email}

Remember to be helpful and confirm actions before executing them.`
    };

    const response = await openai.chat.completions.create({
      model: "qwen-plus",
      messages: [systemMessage, ...messages],
      tools: BOOKING_FUNCTIONS,
      tool_choice: "auto",
      temperature: 0.7,
      max_tokens: 1000
    });

    const assistantMessage = response.choices[0].message;

    if (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
      const toolResults = [];

      for (const toolCall of assistantMessage.tool_calls) {
        const functionName = toolCall.function.name;
        const functionArgs = JSON.parse(toolCall.function.arguments);

        const result = await executeChatFunction(functionName, functionArgs, userContext);

        toolResults.push({
          tool_call_id: toolCall.id,
          role: "tool",
          content: JSON.stringify(result)
        });
      }

      const finalResponse = await openai.chat.completions.create({
        model: "qwen-plus",
        messages: [
          systemMessage,
          ...messages,
          assistantMessage,
          ...toolResults
        ],
        temperature: 0.7,
        max_tokens: 1000
      });

      return res.json({
        success: true,
        message: finalResponse.choices[0].message.content,
        functionsCalled: assistantMessage.tool_calls.map(tc => tc.function.name)
      });
    }

    res.json({
      success: true,
      message: assistantMessage.content,
      functionsCalled: []
    });

  } catch (error) {
    console.error('AI Chat Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to process chat request' });
  }
});

export default app;
