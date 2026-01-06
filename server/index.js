import express from 'express';
import cors from 'cors';
import pg from 'pg';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { body, query, validationResult } from 'express-validator';
import { OAuth2Client } from 'google-auth-library';

// Load environment variables BEFORE importing modules that need them
dotenv.config();

import * as AIService from './ai-service.js';

const isProduction = process.env.NODE_ENV === 'production';
const AUTH_COOKIE_NAME = 'nm_auth';
const AUTH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60 * 1000;
const REQUEST_BODY_LIMIT = process.env.REQUEST_BODY_LIMIT || '100kb';
const ALLOWED_ZONES = ['Main Campus', 'Diaspora', 'Night Market', 'Pent & Beyond'];
const ALLOWED_STATUSES = ['pending', 'confirmed', 'cancelled', 'completed'];

function isStrongSecret(secret) {
  return !!secret && Buffer.byteLength(secret, 'utf8') >= 32;
}

function resolveJwtSecret() {
  if (isStrongSecret(process.env.JWT_SECRET)) {
    return process.env.JWT_SECRET;
  }
  if (isProduction) {
    if (process.env.DATABASE_URL) {
      console.warn('JWT_SECRET is not set or too short. Deriving a fallback from DATABASE_URL.');
      return crypto.createHash('sha256').update(process.env.DATABASE_URL).digest('hex');
    }
    throw new Error('JWT_SECRET must be set to a strong value (>= 32 bytes).');
  }
  const devSecret = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET is not set or too short. Generated a temporary dev secret.');
  return devSecret;
}

// JWT Configuration
const JWT_SECRET = resolveJwtSecret();
const JWT_EXPIRES_IN = '7d';

// Google OAuth Configuration
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '220954600657-lhumhi9v61511qohdsttjjqgadsf0ken.apps.googleusercontent.com';
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3001;

// Booking capacity configuration
const DAILY_BIKE_LIMIT = 20; // Maximum bookings per day (first 20 can book any slot)

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: 'lax',
  maxAge: AUTH_COOKIE_MAX_AGE,
  path: '/'
};
const CLEAR_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: isProduction,
  sameSite: 'lax',
  path: '/'
};

const defaultCorsOrigins = isProduction
  ? []
  : ['http://localhost:3000', 'http://localhost:3001'];
const configuredCorsOrigins = (process.env.CORS_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const corsOrigins = configuredCorsOrigins.length > 0 ? configuredCorsOrigins : defaultCorsOrigins;
const allowAllOrigins = corsOrigins.length === 0;
if (isProduction && allowAllOrigins) {
  console.warn('CORS_ORIGINS not set in production; allowing all origins.');
}

const corsOptions = {
  origin(origin, callback) {
    if (!origin) return callback(null, true);
    if (allowAllOrigins || corsOrigins.includes(origin)) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  optionsSuccessStatus: 204
};

const rateLimitWindowMs = Number(process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000);
const apiLimiter = rateLimit({
  windowMs: rateLimitWindowMs,
  max: Number(process.env.RATE_LIMIT_MAX || 300),
  standardHeaders: true,
  legacyHeaders: false
});
const authLimiter = rateLimit({
  windowMs: rateLimitWindowMs,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false
});

// Middleware
app.set('trust proxy', 1);
app.disable('x-powered-by');
if (isProduction) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] && req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect(308, `https://${req.headers.host}${req.originalUrl}`);
    }
    next();
  });
}
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));
app.use(cors(corsOptions));
app.use(express.json({ limit: REQUEST_BODY_LIMIT }));
app.use(express.urlencoded({ extended: false, limit: REQUEST_BODY_LIMIT }));
app.use('/api/auth', authLimiter);
app.use('/api', apiLimiter);

// Serve static frontend files
app.use(express.static(path.join(__dirname, '..')));

// Database connection
const connectionConfig = {
  connectionString: process.env.DATABASE_URL,
  ssl: isProduction ? { rejectUnauthorized: false } : false,
  max: Number(process.env.DB_POOL_MAX || 20),
  idleTimeoutMillis: Number(process.env.DB_POOL_IDLE_MS || 30000),
  connectionTimeoutMillis: Number(process.env.DB_POOL_CONN_MS || 2000)
};

// Fallback to individual params if DATABASE_URL is not set (e.g. local dev)
if (!process.env.DATABASE_URL) {
  connectionConfig.host = process.env.DB_HOST || 'localhost';
  connectionConfig.port = process.env.DB_PORT || 5432;
  connectionConfig.database = process.env.DB_NAME || 'night_market';
  connectionConfig.user = process.env.DB_USER || 'patrickannor';
  connectionConfig.password = process.env.DB_PASSWORD || '';
  delete connectionConfig.connectionString;
  delete connectionConfig.ssl;
}

const pool = new pg.Pool(connectionConfig);

// Test database connection
pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Database connection error:', err.message);
  } else {
    console.log('Database connected successfully');
  }
});

// Helper: Generate booking ID
function generateBookingId() {
  const num = Math.floor(1000 + Math.random() * 9000);
  return `BK-${num}`;
}

// Helper: Calculate end time
function calculateEndTime(startTime, durationMinutes) {
  const [hours, minutes] = startTime.split(':').map(Number);
  const totalMinutes = hours * 60 + minutes + durationMinutes;
  const endHours = Math.floor(totalMinutes / 60) % 24;
  const endMins = totalMinutes % 60;
  return `${String(endHours).padStart(2, '0')}:${String(endMins).padStart(2, '0')}`;
}

// Helper: Calculate cost (free service - always returns 0)
function calculateCost(durationMinutes, hourlyRate = 0) {
  return 0;
}

function toDateString(value) {
  if (!value) return null;
  if (value instanceof Date) return value.toISOString().split('T')[0];
  if (typeof value === 'string') return value.split('T')[0];
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed.toISOString().split('T')[0];
}

function parseCookies(cookieHeader) {
  const cookies = {};
  if (!cookieHeader) return cookies;
  cookieHeader.split(';').forEach(pair => {
    const [name, ...valueParts] = pair.trim().split('=');
    if (!name) return;
    cookies[name] = decodeURIComponent(valueParts.join('='));
  });
  return cookies;
}

function getTokenFromRequest(req) {
  const authHeader = req.headers['authorization'];
  if (authHeader) {
    const [scheme, token] = authHeader.split(' ');
    if (scheme === 'Bearer' && token) {
      return token;
    }
  }
  const cookies = parseCookies(req.headers.cookie);
  return cookies[AUTH_COOKIE_NAME];
}

function setAuthCookie(res, token) {
  res.cookie(AUTH_COOKIE_NAME, token, COOKIE_OPTIONS);
}

function clearAuthCookie(res) {
  res.clearCookie(AUTH_COOKIE_NAME, CLEAR_COOKIE_OPTIONS);
}

function handleValidationErrors(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Invalid request data',
      errors: errors.array().map(err => ({ field: err.path, message: err.msg }))
    });
  }
  next();
}

const authValidators = [
  body('name').trim().isLength({ min: 1, max: 100 }).withMessage('Name is required'),
  body('phone')
    .trim()
    .isLength({ min: 8, max: 20 })
    .withMessage('Phone number is required'),
  handleValidationErrors
];

const googleAuthValidators = [
  body('credential').trim().notEmpty().withMessage('Google credential is required'),
  handleValidationErrors
];

const bookingCreateValidators = [
  body('rider_id').trim().notEmpty().withMessage('rider_id is required'),
  body('rider_name').trim().notEmpty().withMessage('rider_name is required'),
  body('rider_email').isEmail().withMessage('rider_email must be a valid email'),
  body('booking_date')
    .matches(/^\d{4}-\d{2}-\d{2}$/)
    .withMessage('booking_date must be in YYYY-MM-DD format'),
  body('start_time')
    .matches(/^\d{2}:\d{2}$/)
    .withMessage('start_time must be in HH:MM format'),
  body('duration_minutes')
    .isInt({ min: 15, max: 480 })
    .withMessage('duration_minutes must be between 15 and 480 minutes'),
  body('zone').optional().isIn(ALLOWED_ZONES).withMessage('zone must be a valid zone'),
  handleValidationErrors
];

const bookingQueryValidators = [
  query('date')
    .optional()
    .matches(/^\d{4}-\d{2}-\d{2}$/)
    .withMessage('date must be in YYYY-MM-DD format'),
  query('rider_id')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('rider_id must be provided'),
  query('zone').optional().isIn(ALLOWED_ZONES).withMessage('zone must be a valid zone'),
  query('status').optional().isIn(ALLOWED_STATUSES).withMessage('status must be valid'),
  handleValidationErrors
];

const adminBookingsQueryValidators = [
  query('status')
    .optional()
    .isIn(['all', ...ALLOWED_STATUSES])
    .withMessage('status must be valid'),
  query('search')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('search must be between 1 and 100 characters'),
  query('limit').optional().isInt({ min: 1, max: 200 }).withMessage('limit must be between 1 and 200'),
  query('offset').optional().isInt({ min: 0, max: 10000 }).withMessage('offset must be between 0 and 10000'),
  handleValidationErrors
];

const adminBookingStatusValidators = [
  body('status').isIn(ALLOWED_STATUSES).withMessage('Invalid status'),
  handleValidationErrors
];

// Validation middleware
function validateBookingData(req, res, next) {
  const { rider_id, rider_name, rider_email, booking_date, start_time, duration_minutes, zone } = req.body;

  const errors = [];

  if (!rider_id) errors.push('rider_id is required');
  if (!rider_name) errors.push('rider_name is required');
  if (!rider_email) errors.push('rider_email is required');
  if (!booking_date) errors.push('booking_date is required (YYYY-MM-DD)');
  if (!start_time) errors.push('start_time is required (HH:MM)');
  if (!duration_minutes) errors.push('duration_minutes is required');

  // Validate date format
  if (booking_date && !/^\d{4}-\d{2}-\d{2}$/.test(booking_date)) {
    errors.push('booking_date must be in YYYY-MM-DD format');
  }

  // Validate time format
  if (start_time && !/^\d{2}:\d{2}$/.test(start_time)) {
    errors.push('start_time must be in HH:MM format');
  }

  // Validate duration (allow any reasonable duration between 15 minutes and 8 hours)
  const durationNum = Number(duration_minutes);
  if (duration_minutes && (isNaN(durationNum) || durationNum < 15 || durationNum > 480)) {
    errors.push('duration_minutes must be between 15 and 480 minutes');
  }

  // Validate email format
  if (rider_email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(rider_email)) {
    errors.push('rider_email must be a valid email address');
  }

  if (zone && !ALLOWED_ZONES.includes(zone)) {
    errors.push('zone must be one of: ' + ALLOWED_ZONES.join(', '));
  }

  if (errors.length > 0) {
    return res.status(400).json({
      success: false,
      error: 'VALIDATION_ERROR',
      message: 'Missing or invalid required fields',
      errors,
      required_fields: {
        rider_id: 'string - Rider unique identifier',
        rider_name: 'string - Rider full name',
        rider_email: 'string - Valid email address',
        booking_date: 'string - Date in YYYY-MM-DD format',
        start_time: 'string - Time in HH:MM format',
        duration_minutes: 'number - Duration (15 to 480 minutes)'
      }
    });
  }

  next();
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const token = getTokenFromRequest(req);

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

// Admin authorization middleware
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

// Helper: Generate rider ID
function generateRiderId() {
  const num = Math.floor(10000 + Math.random() * 90000);
  return `RDR-${num}`;
}

// Helper: Normalize phone number to +233 format for database storage/lookup
function normalizePhone(phone) {
  if (!phone) return '';
  // Remove all non-digit characters
  let cleaned = phone.replace(/\D/g, '');
  // Convert local format (0XX) to international (+233)
  if (cleaned.startsWith('0')) {
    cleaned = '+233' + cleaned.slice(1);
  } else if (cleaned.startsWith('233')) {
    cleaned = '+' + cleaned;
  } else if (!cleaned.startsWith('+')) {
    cleaned = '+233' + cleaned;
  }
  return cleaned;
}

// =====================
// AUTH ROUTES
// =====================

// Register new rider (using name and phone - matching frontend)
app.post('/api/auth/register', authValidators, async (req, res) => {
  try {
    const { name, phone } = req.body;

    // Validate required fields
    if (!name || !phone) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Name and phone number are required'
      });
    }

    // Normalize phone number to +233 format
    const normalizedPhone = normalizePhone(phone);

    // Check if phone number already exists
    const existingUser = await pool.query(
      'SELECT id FROM riders WHERE phone = $1',
      [normalizedPhone]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'PHONE_EXISTS',
        message: 'An account with this phone number already exists'
      });
    }

    // Generate unique rider ID
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

    // Generate placeholder email from phone (required by schema)
    const placeholderEmail = `${normalizedPhone.replace(/\D/g, '')}@rider.nightmarket.local`;

    // Insert new rider
    const result = await pool.query(
      `INSERT INTO riders (rider_id, name, email, phone, role, is_verified)
       VALUES ($1, $2, $3, $4, 'rider', FALSE)
       RETURNING rider_id, name, email, phone, role, is_verified, created_at`,
      [riderId, name, placeholderEmail, normalizedPhone]
    );

    const rider = result.rows[0];

    // Generate JWT token
    const token = jwt.sign(
      { rider_id: rider.rider_id, phone: rider.phone, role: rider.role },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    setAuthCookie(res, token);
    res.status(201).json({
      success: true,
      message: 'Account created successfully',
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

// Login (using name and phone - matching frontend)
app.post('/api/auth/login', authValidators, async (req, res) => {
  try {
    const { name, phone } = req.body;

    // Validate required fields
    if (!name || !phone) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Name and phone number are required'
      });
    }

    // Normalize phone number and find user
    const normalizedPhone = normalizePhone(phone);
    // Also try various formats for backwards compatibility
    const phoneDigits = phone.replace(/\D/g, '');
    const phoneWithZero = phoneDigits.startsWith('233') ? '0' + phoneDigits.slice(3) : (phoneDigits.startsWith('0') ? phoneDigits : '0' + phoneDigits);
    // Handle format with space after country code: +233 XXXXXXXXX
    const phoneWithSpace = phoneDigits.startsWith('0')
      ? '+233 ' + phoneDigits.slice(1)
      : (phoneDigits.startsWith('233') ? '+233 ' + phoneDigits.slice(3) : '+233 ' + phoneDigits);

    const result = await pool.query(
      'SELECT * FROM riders WHERE phone = $1 OR phone = $2 OR phone = $3 OR phone = $4 OR phone = $5',
      [normalizedPhone, phoneDigits, phoneWithZero, '+' + phoneDigits, phoneWithSpace]
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

    // Generate JWT token
    const token = jwt.sign(
      { rider_id: rider.rider_id, phone: rider.phone, role: rider.role || 'rider' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    setAuthCookie(res, token);
    res.json({
      success: true,
      message: 'Login successful',
      user: {
        rider_id: rider.rider_id,
        name: rider.name,
        email: rider.email,
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

app.post('/api/auth/logout', (req, res) => {
  clearAuthCookie(res);
  res.json({ success: true, message: 'Logged out' });
});

// Google OAuth Login
app.post('/api/auth/google', googleAuthValidators, async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Google credential is required'
      });
    }

    // Verify Google ID token
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;

    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Email not provided by Google'
      });
    }

    // Check if user already exists
    let result = await pool.query(
      'SELECT * FROM riders WHERE email = $1',
      [email.toLowerCase()]
    );

    let rider;
    let isNewUser = false;

    if (result.rows.length === 0) {
      // Create new user
      isNewUser = true;

      // Generate unique rider ID
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

      // Insert new rider (no password for Google users)
      const insertResult = await pool.query(
        `INSERT INTO riders (rider_id, name, email, avatar_url, role, is_verified)
         VALUES ($1, $2, $3, $4, 'rider', TRUE)
         RETURNING rider_id, name, email, phone, role, is_verified, avatar_url, created_at`,
        [riderId, name, email.toLowerCase(), picture || null]
      );

      rider = insertResult.rows[0];
    } else {
      rider = result.rows[0];

      // Update avatar if not set
      if (!rider.avatar_url && picture) {
        await pool.query(
          `UPDATE riders SET 
           avatar_url = $1,
           updated_at = CURRENT_TIMESTAMP
           WHERE rider_id = $2`,
          [picture, rider.rider_id]
        );
        rider.avatar_url = picture;
      }
    }

    // Generate JWT token
    const token = jwt.sign(
      { rider_id: rider.rider_id, email: rider.email, role: rider.role || 'rider' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES_IN }
    );

    setAuthCookie(res, token);
    res.json({
      success: true,
      message: isNewUser ? 'Account created successfully' : 'Login successful',
      user: {
        rider_id: rider.rider_id,
        name: rider.name,
        email: rider.email,
        phone: rider.phone,
        role: rider.role || 'rider',
        is_verified: rider.is_verified,
        avatar_url: rider.avatar_url
      }
    });

  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred during Google authentication'
    });
  }
});

// =====================
// PUBLIC ROUTES
// =====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Create booking
app.post('/api/bookings', bookingCreateValidators, validateBookingData, async (req, res) => {
  const client = await pool.connect();

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
    // Free service - no cost
    const hourly_rate = 0;
    const total_cost = 0;

    // Step 1: Count total bookings for the day (20-bike capacity system)
    const dailyCountQuery = `
      SELECT COUNT(*) as daily_count
      FROM bookings
      WHERE booking_date = $1 AND status != 'cancelled'
    `;
    const dailyCountResult = await client.query(dailyCountQuery, [booking_date]);
    const dailyBookingCount = parseInt(dailyCountResult.rows[0].daily_count);

    // Step 2: Check availability based on daily capacity
    // First 20 bookings can choose any slot; after that, only empty slots are available
    if (dailyBookingCount >= DAILY_BIKE_LIMIT) {
      // Daily limit reached - only allow booking if the requested time slot is completely empty
      const slotConflictQuery = `
        SELECT COUNT(*) as slot_count
        FROM bookings
        WHERE booking_date = $1
          AND status != 'cancelled'
          AND start_time < $3
          AND end_time > $2
      `;
      const slotResult = await client.query(slotConflictQuery, [
        booking_date,
        start_time,
        end_time
      ]);

      if (parseInt(slotResult.rows[0].slot_count) > 0) {
        return res.status(409).json({
          success: false,
          error: 'SLOT_UNAVAILABLE',
          message: 'Daily capacity reached (20 bikes). Only completely empty time slots are available.',
          daily_count: dailyBookingCount,
          daily_limit: DAILY_BIKE_LIMIT,
          requested_slot: {
            date: booking_date,
            start_time,
            end_time,
            zone
          }
        });
      }
    }
    // If dailyBookingCount < DAILY_BIKE_LIMIT, any slot is allowed (no conflict check needed)

    // Generate unique booking ID
    let booking_id;
    let isUnique = false;

    while (!isUnique) {
      booking_id = generateBookingId();
      const checkResult = await client.query(
        'SELECT 1 FROM bookings WHERE booking_id = $1',
        [booking_id]
      );
      isUnique = checkResult.rows.length === 0;
    }

    // Insert booking
    const insertQuery = `
      INSERT INTO bookings (
        booking_id, rider_id, rider_name, rider_email,
        booking_date, start_time, end_time, duration_minutes,
        zone, hourly_rate, total_cost, status
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *
    `;

    const insertResult = await client.query(insertQuery, [
      booking_id,
      rider_id,
      rider_name,
      rider_email,
      booking_date,
      start_time,
      end_time,
      duration_minutes,
      zone,
      hourly_rate,
      total_cost,
      'confirmed'
    ]);

    const booking = insertResult.rows[0];

    res.status(201).json({
      success: true,
      message: 'Booking created successfully',
      booking: {
        booking_id: booking.booking_id,
        rider_id: booking.rider_id,
        rider_name: booking.rider_name,
        booking_date: booking.booking_date,
        start_time: booking.start_time,
        end_time: booking.end_time,
        duration_minutes: booking.duration_minutes,
        zone: booking.zone,
        total_cost: parseFloat(booking.total_cost),
        status: booking.status,
        created_at: booking.created_at
      }
    });

  } catch (error) {
    console.error('Error creating booking:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while creating the booking. Please try again.'
    });
  } finally {
    client.release();
  }
});

// Get all bookings (with optional filters)
app.get('/api/bookings', bookingQueryValidators, async (req, res) => {
  try {
    const { date, rider_id, zone, status } = req.query;

    let query = 'SELECT * FROM bookings WHERE 1=1';
    const params = [];
    let paramIndex = 1;

    if (date) {
      query += ` AND booking_date = $${paramIndex++}`;
      params.push(date);
    }
    if (rider_id) {
      query += ` AND rider_id = $${paramIndex++}`;
      params.push(rider_id);
    }
    if (zone) {
      query += ` AND zone = $${paramIndex++}`;
      params.push(zone);
    }
    if (status) {
      query += ` AND status = $${paramIndex++}`;
      params.push(status);
    }

    query += ' ORDER BY booking_date DESC, start_time ASC';

    const result = await pool.query(query, params);

    res.json({
      success: true,
      count: result.rows.length,
      bookings: result.rows
    });

  } catch (error) {
    console.error('Error fetching bookings:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while fetching bookings.'
    });
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
      const dateStr = toDateString(row.booking_date);
      if (dateStr) {
        dailyCounts[dateStr] = parseInt(row.daily_count);
      }
    });

    // Group bookings by date
    const bookingsByDate = {};
    bookingsResult.rows.forEach(booking => {
      const dateStr = toDateString(booking.booking_date);
      if (!dateStr) {
        return;
      }
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

    // Disable caching so schedule reflects admin changes immediately
    res.set('Cache-Control', 'no-store');

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

// Get single booking by ID
app.get('/api/bookings/:bookingId', async (req, res) => {
  try {
    const { bookingId } = req.params;

    const result = await pool.query(
      'SELECT * FROM bookings WHERE booking_id = $1',
      [bookingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: `Booking ${bookingId} not found`
      });
    }

    res.json({
      success: true,
      booking: result.rows[0]
    });

  } catch (error) {
    console.error('Error fetching booking:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while fetching the booking.'
    });
  }
});

// Cancel booking
app.patch('/api/bookings/:bookingId/cancel', async (req, res) => {
  try {
    const { bookingId } = req.params;

    const result = await pool.query(
      `UPDATE bookings
       SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP
       WHERE booking_id = $1 AND status != 'cancelled'
       RETURNING *`,
      [bookingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: `Booking ${bookingId} not found or already cancelled`
      });
    }

    res.json({
      success: true,
      message: 'Booking cancelled successfully',
      booking: result.rows[0]
    });

  } catch (error) {
    console.error('Error cancelling booking:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while cancelling the booking.'
    });
  }
});

// Reschedule booking
app.patch('/api/bookings/:bookingId/reschedule', async (req, res) => {
  const client = await pool.connect();

  try {
    const { bookingId } = req.params;
    const { booking_date, start_time, duration_minutes } = req.body;

    // Validate required fields
    if (!booking_date || !start_time) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'booking_date and start_time are required'
      });
    }

    // Validate date format
    if (!/^\d{4}-\d{2}-\d{2}$/.test(booking_date)) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'booking_date must be in YYYY-MM-DD format'
      });
    }

    // Validate time format
    if (!/^\d{2}:\d{2}$/.test(start_time)) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'start_time must be in HH:MM format'
      });
    }

    // Get existing booking
    const existingBooking = await client.query(
      'SELECT * FROM bookings WHERE booking_id = $1',
      [bookingId]
    );

    if (existingBooking.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'NOT_FOUND',
        message: `Booking ${bookingId} not found`
      });
    }

    const booking = existingBooking.rows[0];

    // Check if booking can be rescheduled
    if (booking.status === 'cancelled' || booking.status === 'completed') {
      return res.status(400).json({
        success: false,
        error: 'INVALID_STATUS',
        message: 'Cancelled or completed bookings cannot be rescheduled'
      });
    }

    // Use existing duration if not provided
    const newDuration = duration_minutes || booking.duration_minutes;
    const end_time = calculateEndTime(start_time, newDuration);
    const total_cost = calculateCost(newDuration, booking.hourly_rate);

    // Check for conflicting bookings (excluding current booking)
    const conflictQuery = `
      SELECT booking_id, start_time, end_time
      FROM bookings
      WHERE booking_date = $1
        AND zone = $2
        AND status != 'cancelled'
        AND booking_id != $3
        AND (
          (start_time <= $4 AND end_time > $4)
          OR (start_time < $5 AND end_time >= $5)
          OR (start_time >= $4 AND end_time <= $5)
        )
    `;

    const conflictResult = await client.query(conflictQuery, [
      booking_date,
      booking.zone,
      bookingId,
      start_time,
      end_time
    ]);

    if (conflictResult.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'SLOT_UNAVAILABLE',
        message: 'The requested time slot is not available. Please choose a different time.',
        conflicting_bookings: conflictResult.rows
      });
    }

    // Update the booking
    const updateResult = await client.query(
      `UPDATE bookings
       SET booking_date = $1, start_time = $2, end_time = $3, duration_minutes = $4, total_cost = $5, updated_at = CURRENT_TIMESTAMP
       WHERE booking_id = $6
       RETURNING *`,
      [booking_date, start_time, end_time, newDuration, total_cost, bookingId]
    );

    res.json({
      success: true,
      message: 'Booking rescheduled successfully',
      booking: updateResult.rows[0]
    });

  } catch (error) {
    console.error('Error rescheduling booking:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while rescheduling the booking.'
    });
  } finally {
    client.release();
  }
});

// Get available time slots for a date
app.get('/api/availability', async (req, res) => {
  try {
    const { date, zone = 'Main Campus' } = req.query;

    if (!date) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'date query parameter is required (YYYY-MM-DD)'
      });
    }

    // Count total daily bookings (across all zones) for 20-bike capacity system
    const dailyCountResult = await pool.query(
      `SELECT COUNT(*) as daily_count
       FROM bookings
       WHERE booking_date = $1 AND status != 'cancelled'`,
      [date]
    );
    const dailyCount = parseInt(dailyCountResult.rows[0].daily_count);
    const isEarlyBird = dailyCount < DAILY_BIKE_LIMIT;

    // Get all bookings for the date (across all zones for visibility)
    const result = await pool.query(
      `SELECT start_time, end_time, duration_minutes, zone, rider_name
       FROM bookings
       WHERE booking_date = $1 AND status != 'cancelled'
       ORDER BY start_time`,
      [date]
    );

    // Generate all possible time slots (8 AM to 10 PM)
    const allSlots = [];
    for (let hour = 8; hour < 22; hour++) {
      allSlots.push(`${String(hour).padStart(2, '0')}:00`);
      allSlots.push(`${String(hour).padStart(2, '0')}:30`);
    }

    // Map bookings to slot info
    const bookedSlots = result.rows.map(b => ({
      start: b.start_time.slice(0, 5),
      end: b.end_time.slice(0, 5),
      zone: b.zone,
      rider_name: b.rider_name
    }));

    const availability = allSlots.map(slot => {
      const overlappingBookings = bookedSlots.filter(booked =>
        slot >= booked.start && slot < booked.end
      );
      const hasBookings = overlappingBookings.length > 0;

      return {
        time: slot,
        // Early bird users can book any slot; others need empty slots
        available: isEarlyBird || !hasBookings,
        booking_count: overlappingBookings.length,
        has_bookings: hasBookings
      };
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
    console.error('Error checking availability:', error);
    res.status(500).json({
      success: false,
      error: 'SERVER_ERROR',
      message: 'An error occurred while checking availability.'
    });
  }
});

// =====================
// NOTIFICATION ROUTES
// =====================

// Helper: Create notification
async function createNotification(riderId, type, title, message, bookingId = null) {
  try {
    await pool.query(`INSERT INTO notifications (rider_id, type, title, message, booking_id) VALUES ($1, $2, $3, $4, $5)`, [riderId, type, title, message, bookingId]);
  } catch (error) { console.error('Error creating notification:', error); }
}

// Get user's notifications
app.get('/api/notifications', authenticateToken, async (req, res) => {
  try {
    const { type, is_read, limit = 50, offset = 0 } = req.query;
    let query = 'SELECT * FROM notifications WHERE rider_id = $1';
    const params = [req.user.rider_id];
    let paramIndex = 2;
    if (type) { query += ` AND type = $${paramIndex++}`; params.push(type); }
    if (is_read !== undefined) { query += ` AND is_read = $${paramIndex++}`; params.push(is_read === 'true'); }
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(parseInt(limit), parseInt(offset));
    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rows.length, notifications: result.rows });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch notifications.' }); }
});

// Get unread notification count
app.get('/api/notifications/count', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT COUNT(*) FROM notifications WHERE rider_id = $1 AND is_read = FALSE', [req.user.rider_id]);
    res.json({ success: true, unread_count: parseInt(result.rows[0].count) });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to count notifications.' }); }
});

// Mark notification as read
app.patch('/api/notifications/:id/read', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE notifications SET is_read = TRUE WHERE id = $1 AND rider_id = $2 RETURNING *`, [req.params.id, req.user.rider_id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'Notification not found' });
    res.json({ success: true, notification: result.rows[0] });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to update notification.' }); }
});

// Mark all notifications as read
app.put('/api/notifications/read-all', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(`UPDATE notifications SET is_read = TRUE WHERE rider_id = $1 AND is_read = FALSE`, [req.user.rider_id]);
    res.json({ success: true, message: 'All notifications marked as read', updated_count: result.rowCount });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to update notifications.' }); }
});

// Generate AI-powered smart notification for user
app.post('/api/notifications/smart', authenticateToken, async (req, res) => {
  try {
    const riderId = req.user.rider_id;

    // Get user info
    const userResult = await pool.query(
      'SELECT name, preferred_zone FROM riders WHERE rider_id = $1',
      [riderId]
    );

    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'User not found' });
    }

    const user = userResult.rows[0];

    // Get user's upcoming bookings
    const today = new Date().toISOString().split('T')[0];
    const upcomingResult = await pool.query(
      `SELECT * FROM bookings WHERE rider_id = $1 AND booking_date >= $2 AND status = 'confirmed' ORDER BY booking_date, start_time LIMIT 1`,
      [riderId, today]
    );

    // Get user's booking history
    const historyResult = await pool.query(
      `SELECT * FROM bookings WHERE rider_id = $1 ORDER BY booking_date DESC LIMIT 10`,
      [riderId]
    );

    // Determine notification type
    let notificationType = 'personalized_promotion';
    let context = {
      rider_name: user.name,
      preferred_zone: user.preferred_zone || 'Main Campus'
    };

    if (upcomingResult.rows.length > 0) {
      // User has upcoming booking - send reminder
      const nextBooking = upcomingResult.rows[0];
      const bookingDate = new Date(nextBooking.booking_date);
      const now = new Date();
      const diffHours = Math.round((bookingDate - now) / (1000 * 60 * 60));

      if (diffHours <= 24 && diffHours > 0) {
        notificationType = 'booking_reminder';
        context = {
          booking_id: nextBooking.booking_id,
          booking_date: nextBooking.booking_date,
          start_time: nextBooking.start_time,
          end_time: nextBooking.end_time,
          zone: nextBooking.zone,
          rider_name: user.name,
          time_until: diffHours <= 1 ? `${diffHours * 60} minutes` : `${diffHours} hours`
        };
      }
    } else if (historyResult.rows.length > 0) {
      // User has history but no upcoming - send re-engagement
      const lastBooking = historyResult.rows[0];
      const lastDate = new Date(lastBooking.booking_date);
      const now = new Date();
      const daysSince = Math.round((now - lastDate) / (1000 * 60 * 60 * 24));

      // Analyze preferred time
      const hours = historyResult.rows.map(b => parseInt(b.start_time.split(':')[0]));
      const avgHour = Math.round(hours.reduce((a, b) => a + b, 0) / hours.length);
      const preferredTime = avgHour < 12 ? 'morning' : avgHour < 17 ? 'afternoon' : 'evening';

      context = {
        rider_name: user.name,
        last_booking_date: lastBooking.booking_date,
        days_inactive: daysSince,
        preferred_zone: user.preferred_zone || lastBooking.zone,
        preferred_time: preferredTime
      };
    }

    // Generate AI notification
    const notification = await AIService.generateNotification(notificationType, context);

    if (notification.success) {
      // Save to database
      await pool.query(
        `INSERT INTO notifications (rider_id, type, title, message) VALUES ($1, $2, $3, $4)`,
        [riderId, notificationType, notification.title, notification.message]
      );

      res.json({
        success: true,
        notification: {
          type: notificationType,
          title: notification.title,
          message: notification.message
        }
      });
    } else {
      res.status(500).json({ success: false, error: 'AI_ERROR', message: 'Failed to generate notification' });
    }

  } catch (error) {
    console.error('Smart Notification Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to generate smart notification' });
  }
});

// Generate booking reminder notifications (for cron job)
app.post('/api/notifications/generate-reminders', async (req, res) => {
  try {
    // This would typically be called by a cron job
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];

    // Find all confirmed bookings for tomorrow
    const bookingsResult = await pool.query(
      `SELECT b.*, r.name as rider_name FROM bookings b 
       JOIN riders r ON b.rider_id = r.rider_id 
       WHERE b.booking_date = $1 AND b.status = 'confirmed'`,
      [tomorrowStr]
    );

    let generatedCount = 0;

    for (const booking of bookingsResult.rows) {
      try {
        const context = {
          booking_id: booking.booking_id,
          booking_date: booking.booking_date,
          start_time: booking.start_time,
          end_time: booking.end_time,
          zone: booking.zone,
          rider_name: booking.rider_name,
          time_until: 'tomorrow'
        };

        const notification = await AIService.generateNotification('booking_reminder', context);

        if (notification.success) {
          await pool.query(
            `INSERT INTO notifications (rider_id, type, title, message, booking_id) VALUES ($1, $2, $3, $4, $5)`,
            [booking.rider_id, 'booking_reminder', notification.title, notification.message, booking.booking_id]
          );
          generatedCount++;
        }
      } catch (err) {
        console.error('Error generating reminder for booking:', booking.booking_id, err);
      }
    }

    res.json({
      success: true,
      message: `Generated ${generatedCount} reminder notifications`,
      count: generatedCount
    });

  } catch (error) {
    console.error('Reminder Generation Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to generate reminders' });
  }
});

// =====================
// NOTIFICATION SETTINGS ROUTES
// =====================

app.get('/api/notification-settings', authenticateToken, async (req, res) => {
  try {
    let result = await pool.query('SELECT * FROM notification_settings WHERE rider_id = $1', [req.user.rider_id]);
    if (result.rows.length === 0) result = await pool.query(`INSERT INTO notification_settings (rider_id) VALUES ($1) RETURNING *`, [req.user.rider_id]);
    res.json({ success: true, settings: result.rows[0] });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch settings.' }); }
});

app.put('/api/notification-settings', authenticateToken, async (req, res) => {
  try {
    const { enable_all, email_enabled, sms_enabled, in_app_enabled, reminder_timing, confirmation_timing, cancellation_alerts } = req.body;
    const result = await pool.query(`INSERT INTO notification_settings (rider_id, enable_all, email_enabled, sms_enabled, in_app_enabled, reminder_timing, confirmation_timing, cancellation_alerts) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (rider_id) DO UPDATE SET enable_all = COALESCE($2, notification_settings.enable_all), email_enabled = COALESCE($3, notification_settings.email_enabled), sms_enabled = COALESCE($4, notification_settings.sms_enabled), in_app_enabled = COALESCE($5, notification_settings.in_app_enabled), reminder_timing = COALESCE($6, notification_settings.reminder_timing), confirmation_timing = COALESCE($7, notification_settings.confirmation_timing), cancellation_alerts = COALESCE($8, notification_settings.cancellation_alerts), updated_at = CURRENT_TIMESTAMP RETURNING *`, [req.user.rider_id, enable_all, email_enabled, sms_enabled, in_app_enabled, reminder_timing, confirmation_timing, cancellation_alerts]);
    res.json({ success: true, message: 'Settings updated successfully', settings: result.rows[0] });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to update settings.' }); }
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
    res.json({ success: true, stats: { active_riders: parseInt(activeResult.rows[0].count), bookings_today: parseInt(bookingsTodayResult.rows[0].count), pending: parseInt(pendingResult.rows[0].count), revenue_today: parseFloat(revenueResult.rows[0].total) } });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch stats.' }); }
});

app.get('/api/admin/bookings', authenticateToken, requireAdmin, adminBookingsQueryValidators, async (req, res) => {
  try {
    const { status, search, limit = 50, offset = 0 } = req.query;
    let query = 'SELECT * FROM bookings WHERE 1=1'; const params = []; let paramIndex = 1;
    if (status && status !== 'all') { query += ` AND status = $${paramIndex++}`; params.push(status); }
    if (search) { query += ` AND (booking_id ILIKE $${paramIndex} OR rider_name ILIKE $${paramIndex})`; params.push(`%${search}%`); paramIndex++; }
    query += ` ORDER BY created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    params.push(parseInt(limit), parseInt(offset));
    const result = await pool.query(query, params);
    res.json({ success: true, count: result.rows.length, bookings: result.rows });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch bookings.' }); }
});

app.patch('/api/admin/bookings/:id/status', authenticateToken, requireAdmin, adminBookingStatusValidators, async (req, res) => {
  try {
    const { status } = req.body;
    const result = await pool.query(`UPDATE bookings SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE booking_id = $2 RETURNING *`, [status, req.params.id]);
    if (result.rows.length === 0) return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'Booking not found' });
    const booking = result.rows[0];
    if (status === 'confirmed' || status === 'cancelled') {
      await createNotification(booking.rider_id, 'booking_' + status, status === 'confirmed' ? 'Booking Approved' : 'Booking Cancelled', `Your booking ${booking.booking_id} has been ${status}.`, booking.booking_id);
    }
    res.json({ success: true, message: `Booking status updated to ${status}`, booking });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to update status.' }); }
});

app.get('/api/admin/riders/recent', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(`SELECT rider_id, name, email, avatar_url, created_at FROM riders WHERE role = 'rider' ORDER BY created_at DESC LIMIT $1`, [parseInt(req.query.limit || 10)]);
    res.json({ success: true, count: result.rows.length, riders: result.rows });
  } catch (error) { res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch riders.' }); }
});

app.get('/api/admin/riders', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit || 50, 10), 200);
    const offset = Math.max(parseInt(req.query.offset || 0, 10), 0);
    const search = req.query.search ? String(req.query.search).trim() : '';

    const params = [];
    let paramIndex = 1;
    let whereClause = "WHERE r.role = 'rider'";

    if (search) {
      whereClause += ` AND (r.name ILIKE $${paramIndex} OR r.email ILIKE $${paramIndex} OR r.phone ILIKE $${paramIndex} OR r.rider_id ILIKE $${paramIndex})`;
      params.push(`%${search}%`);
      paramIndex += 1;
    }

    params.push(limit, offset);

    const query = `
      SELECT
        r.rider_id,
        r.name,
        r.email,
        r.phone,
        r.created_at,
        COUNT(b.booking_id) FILTER (WHERE b.status != 'cancelled') as booking_count,
        MAX(b.booking_date) FILTER (WHERE b.status != 'cancelled') as last_booking_date
      FROM riders r
      LEFT JOIN bookings b ON b.rider_id = r.rider_id
      ${whereClause}
      GROUP BY r.rider_id, r.name, r.email, r.phone, r.created_at
      ORDER BY r.created_at DESC
      LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
    `;

    const result = await pool.query(query, params);
    const riders = result.rows.map(row => {
      const bookingCount = parseInt(row.booking_count || 0, 10);
      return {
        rider_id: row.rider_id,
        name: row.name,
        email: row.email,
        phone: row.phone,
        created_at: row.created_at,
        booking_count: bookingCount,
        last_booking_date: toDateString(row.last_booking_date),
        has_booking: bookingCount > 0
      };
    });

    res.json({ success: true, count: riders.length, riders });
  } catch (error) {
    console.error('Error fetching riders:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to fetch riders.' });
  }
});

// Clear all bookings (Admin only)
app.delete('/api/admin/bookings/clear-all', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM bookings RETURNING booking_id');
    res.json({
      success: true,
      message: `Successfully deleted ${result.rowCount} bookings`,
      deleted_count: result.rowCount
    });
  } catch (error) {
    console.error('Error clearing bookings:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to clear bookings.' });
  }
});

// Update user profile
app.put('/api/profile', authenticateToken, async (req, res) => {
  try {
    const { name, phone, preferred_zone } = req.body;
    const riderId = req.user.rider_id;

    const result = await pool.query(
      `UPDATE riders SET name = COALESCE($1, name), phone = $2, preferred_zone = $3, updated_at = CURRENT_TIMESTAMP 
       WHERE rider_id = $4 RETURNING rider_id, name, email, phone, preferred_zone, role, avatar_url`,
      [name, phone, preferred_zone, riderId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'User not found' });
    }

    res.json({ success: true, message: 'Profile updated successfully', user: result.rows[0] });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to update profile.' });
  }
});

// =====================
// AI ASSISTANT ROUTES
// =====================

// Function executor for AI chatbot
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

      // Generate available slots
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

      // Calculate end time
      const [hours, minutes] = start_time.split(':').map(Number);
      const totalMinutes = hours * 60 + minutes + duration_minutes;
      const endHours = Math.floor(totalMinutes / 60) % 24;
      const endMins = totalMinutes % 60;
      const end_time = `${String(endHours).padStart(2, '0')}:${String(endMins).padStart(2, '0')}`;

      // Free service - no cost
      const hourly_rate = 0;
      const total_cost = 0;

      // Check availability
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

      // Generate booking ID
      let booking_id;
      let isUnique = false;
      while (!isUnique) {
        booking_id = `BK-${Math.floor(1000 + Math.random() * 9000)}`;
        const checkResult = await pool.query('SELECT 1 FROM bookings WHERE booking_id = $1', [booking_id]);
        isUnique = checkResult.rows.length === 0;
      }

      // Insert booking
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
      return {
        bookings: result.rows,
        count: result.rows.length
      };
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

    case 'reschedule_booking': {
      const { booking_id, new_date, new_time } = args;

      // Get existing booking
      const existing = await pool.query(
        'SELECT * FROM bookings WHERE booking_id = $1 AND rider_id = $2',
        [booking_id, userContext.rider_id]
      );

      if (existing.rows.length === 0) {
        return { success: false, error: 'NOT_FOUND', message: 'Booking not found' };
      }

      const booking = existing.rows[0];
      const duration = booking.duration_minutes;

      // Calculate new end time
      const [hours, minutes] = new_time.split(':').map(Number);
      const totalMinutes = hours * 60 + minutes + duration;
      const endHours = Math.floor(totalMinutes / 60) % 24;
      const endMins = totalMinutes % 60;
      const new_end_time = `${String(endHours).padStart(2, '0')}:${String(endMins).padStart(2, '0')}`;

      // Check for conflicts
      const conflictResult = await pool.query(
        `SELECT booking_id FROM bookings WHERE booking_date = $1 AND status != 'cancelled' AND booking_id != $2
         AND ((start_time <= $3 AND end_time > $3) OR (start_time < $4 AND end_time >= $4) OR (start_time >= $3 AND end_time <= $4))`,
        [new_date, booking_id, new_time, new_end_time]
      );

      if (conflictResult.rows.length > 0) {
        return { success: false, error: 'SLOT_UNAVAILABLE', message: 'The new time slot is not available' };
      }

      // Update booking
      const updateResult = await pool.query(
        `UPDATE bookings SET booking_date = $1, start_time = $2, end_time = $3, updated_at = CURRENT_TIMESTAMP 
         WHERE booking_id = $4 RETURNING *`,
        [new_date, new_time, new_end_time, booking_id]
      );

      return { success: true, message: 'Booking rescheduled successfully', booking: updateResult.rows[0] };
    }

    case 'get_recommendations': {
      const userHistory = await pool.query(
        'SELECT * FROM bookings WHERE rider_id = $1 ORDER BY booking_date DESC LIMIT 20',
        [userContext.rider_id]
      );

      // Get crowd data for the week
      const weekStart = new Date();
      const weekEnd = new Date();
      weekEnd.setDate(weekEnd.getDate() + 7);

      const crowdData = await pool.query(
        `SELECT booking_date, EXTRACT(HOUR FROM start_time) as hour, COUNT(*) as count
         FROM bookings WHERE booking_date >= $1 AND booking_date <= $2 AND status != 'cancelled'
         GROUP BY booking_date, EXTRACT(HOUR FROM start_time)`,
        [weekStart.toISOString().split('T')[0], weekEnd.toISOString().split('T')[0]]
      );

      // Simple recommendation logic (AI will enhance this)
      const recommendations = [];
      const preferredHours = {};

      userHistory.rows.forEach(b => {
        const hour = parseInt(b.start_time.split(':')[0]);
        preferredHours[hour] = (preferredHours[hour] || 0) + 1;
      });

      const topHour = Object.entries(preferredHours).sort((a, b) => b[1] - a[1])[0];

      return {
        user_history_count: userHistory.rows.length,
        preferred_time: topHour ? `${topHour[0]}:00` : 'No history',
        crowd_data: crowdData.rows,
        message: 'Based on your history and crowd patterns'
      };
    }

    case 'get_busy_times': {
      const date = args.date || today;

      const result = await pool.query(
        `SELECT start_time, end_time, zone FROM bookings WHERE booking_date = $1 AND status != 'cancelled' ORDER BY start_time`,
        [date]
      );

      const crowdAnalysis = await AIService.getCrowdAnalysis(result.rows, date);
      return crowdAnalysis;
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

    const result = await AIService.chatWithAssistant(messages, userContext, executeChatFunction);

    res.json(result);
  } catch (error) {
    console.error('AI Chat Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to process chat request' });
  }
});

// AI Recommendations endpoint
app.get('/api/ai/recommendations', authenticateToken, async (req, res) => {
  try {
    const riderId = req.user.rider_id;

    const historyResult = await pool.query(
      'SELECT booking_date, start_time, zone FROM bookings WHERE rider_id = $1 ORDER BY booking_date DESC LIMIT 30',
      [riderId]
    );

    const today = new Date();
    const weekEnd = new Date();
    weekEnd.setDate(today.getDate() + 7);

    const crowdResult = await pool.query(
      `SELECT booking_date, EXTRACT(HOUR FROM start_time) as hour, COUNT(*) as count, zone
       FROM bookings WHERE booking_date >= $1 AND booking_date <= $2 AND status != 'cancelled'
       GROUP BY booking_date, EXTRACT(HOUR FROM start_time), zone`,
      [toDateString(today), toDateString(weekEnd)]
    );

    const userResult = await pool.query(
      'SELECT preferred_zone FROM riders WHERE rider_id = $1',
      [riderId]
    );

    const preferredZone = userResult.rows[0]?.preferred_zone || null;
    const userHistory = historyResult.rows;
    const userHistoryCount = userHistory.length;

    const preferredHour = (() => {
      if (userHistory.length === 0) return null;
      const counts = {};
      userHistory.forEach(booking => {
        if (!booking.start_time) return;
        const hour = parseInt(String(booking.start_time).split(':')[0], 10);
        if (Number.isNaN(hour)) return;
        counts[hour] = (counts[hour] || 0) + 1;
      });
      let bestHour = null;
      let bestCount = 0;
      Object.entries(counts).forEach(([hour, count]) => {
        if (count > bestCount) {
          bestCount = count;
          bestHour = parseInt(hour, 10);
        }
      });
      return bestHour;
    })();

    const preferredTime = preferredHour === null
      ? null
      : `${String(preferredHour).padStart(2, '0')}:00`;
    const preferredTimeOfDay = preferredHour === null
      ? null
      : preferredHour < 12
        ? 'Morning'
        : preferredHour < 17
          ? 'Afternoon'
          : 'Evening';
    const bookingFrequency = userHistoryCount === 0
      ? 'No recent bookings'
      : `${userHistoryCount} bookings in last 30 days`;

    const crowdMap = new Map();
    crowdResult.rows.forEach(row => {
      const dateStr = toDateString(row.booking_date);
      if (!dateStr) return;
      const hour = Number(row.hour);
      if (Number.isNaN(hour)) return;
      const zone = row.zone || 'Main Campus';
      const count = Number(row.count || 0);
      crowdMap.set(`${dateStr}|${hour}|${zone}`, count);
    });

    const getCount = (dateStr, hour, zone) => crowdMap.get(`${dateStr}|${hour}|${zone}`) || 0;
    const zonesToConsider = preferredZone ? [preferredZone] : ALLOWED_ZONES;
    const recommendations = [];

    for (let i = 0; i < 7 && recommendations.length < 4; i++) {
      const date = new Date(today);
      date.setDate(today.getDate() + i);
      const dateStr = toDateString(date);
      if (!dateStr) continue;

      let bestSlot = null;
      for (let hour = 8; hour <= 20; hour++) {
        zonesToConsider.forEach(zone => {
          const count = getCount(dateStr, hour, zone);
          const distance = preferredHour === null ? 0 : Math.abs(hour - preferredHour);
          const score = count * 10 + distance;
          if (!bestSlot || score < bestSlot.score) {
            bestSlot = { hour, zone, count, score, distance };
          }
        });
      }

      if (!bestSlot) continue;

      const crowdLevel = bestSlot.count >= 5 ? 'high' : bestSlot.count >= 2 ? 'medium' : 'low';
      const baseConfidence = crowdLevel === 'low' ? 0.75 : crowdLevel === 'medium' ? 0.55 : 0.35;
      const confidenceBoost = (preferredZone && bestSlot.zone === preferredZone ? 0.1 : 0)
        + (bestSlot.distance <= 1 ? 0.05 : 0);
      const confidence = Math.min(0.95, baseConfidence + confidenceBoost);

      const reasonParts = [];
      if (bestSlot.count === 0) {
        reasonParts.push('Wide-open slot');
      } else if (bestSlot.count <= 2) {
        reasonParts.push('Low crowd expected');
      } else if (bestSlot.count <= 4) {
        reasonParts.push('Moderate crowd expected');
      } else {
        reasonParts.push('Popular time with steady demand');
      }
      if (preferredZone && bestSlot.zone === preferredZone) {
        reasonParts.push('Matches your preferred zone');
      }
      if (preferredHour !== null && bestSlot.distance <= 1) {
        reasonParts.push('Close to your usual time');
      }

      recommendations.push({
        date: dateStr,
        time: `${String(bestSlot.hour).padStart(2, '0')}:00`,
        zone: bestSlot.zone,
        reason: reasonParts.join('. '),
        crowd_level: crowdLevel,
        confidence
      });
    }

    if (recommendations.length === 0) {
      const fallbackDate = toDateString(today);
      if (fallbackDate) {
        recommendations.push({
          date: fallbackDate,
          time: '18:00',
          zone: preferredZone || 'Main Campus',
          reason: 'A solid time to get started.',
          crowd_level: 'medium',
          confidence: 0.4
        });
      }
    }

    const llmReasons = await AIService.generateRecommendationReasons(recommendations, {
      preferredZone,
      preferredTimeOfDay,
      userHistoryCount
    });
    if (Array.isArray(llmReasons)) {
      llmReasons.forEach((reason, index) => {
        if (recommendations[index] && reason) {
          recommendations[index].reason = reason;
        }
      });
    }

    res.json({
      success: recommendations.length > 0,
      recommendations,
      insights: {
        preferred_time: preferredTimeOfDay || 'No history yet',
        preferred_zone: preferredZone || 'No preference',
        booking_frequency: bookingFrequency
      },
      user_history_count: userHistoryCount,
      preferred_time: preferredTime
    });
  } catch (error) {
    console.error('AI Recommendations Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to get recommendations' });
  }
});

// AI Demand Analytics (Admin only)
app.get('/api/ai/analytics', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Get historical data for last 30 days
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const historyResult = await pool.query(
      `SELECT booking_date, start_time, end_time, zone, status, duration_minutes, total_cost,
              EXTRACT(DOW FROM booking_date) as day_of_week,
              EXTRACT(HOUR FROM start_time) as hour
       FROM bookings 
       WHERE created_at >= $1
       ORDER BY booking_date`,
      [thirtyDaysAgo.toISOString()]
    );

    // Get daily aggregates
    const dailyStats = await pool.query(
      `SELECT booking_date, COUNT(*) as bookings, SUM(total_cost) as revenue
       FROM bookings WHERE created_at >= $1 AND status != 'cancelled'
       GROUP BY booking_date ORDER BY booking_date`,
      [thirtyDaysAgo.toISOString()]
    );

    const analysis = await AIService.analyzeDemandPatterns({
      bookings: historyResult.rows,
      daily_stats: dailyStats.rows,
      total_bookings: historyResult.rows.length
    });

    res.json(analysis);
  } catch (error) {
    console.error('AI Analytics Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to analyze demand' });
  }
});

// Generate AI notification
app.post('/api/ai/notification', authenticateToken, async (req, res) => {
  try {
    const { type, context } = req.body;

    if (!type) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Notification type is required'
      });
    }

    // Add user info to context
    const userResult = await pool.query(
      'SELECT name FROM riders WHERE rider_id = $1',
      [req.user.rider_id]
    );

    const enrichedContext = {
      ...context,
      rider_name: userResult.rows[0]?.name || 'Rider'
    };

    const notification = await AIService.generateNotification(type, enrichedContext);

    res.json(notification);
  } catch (error) {
    console.error('AI Notification Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to generate notification' });
  }
});

// Natural language search
app.post('/api/ai/search', authenticateToken, async (req, res) => {
  try {
    const { query } = req.body;

    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'VALIDATION_ERROR',
        message: 'Search query is required'
      });
    }

    const context = {
      user_id: req.user.rider_id,
      is_admin: req.user.role === 'admin',
      current_date: new Date().toISOString().split('T')[0]
    };

    const searchParams = await AIService.naturalLanguageSearch(query, context);

    // If we have valid search params, execute the search
    if (searchParams.success) {
      let sqlQuery = 'SELECT * FROM bookings WHERE 1=1';
      const params = [];
      let paramIndex = 1;

      // Only show user's own bookings unless admin
      if (!context.is_admin) {
        sqlQuery += ` AND rider_id = $${paramIndex++}`;
        params.push(req.user.rider_id);
      }

      if (searchParams.date_range?.start) {
        sqlQuery += ` AND booking_date >= $${paramIndex++}`;
        params.push(searchParams.date_range.start);
      }
      if (searchParams.date_range?.end) {
        sqlQuery += ` AND booking_date <= $${paramIndex++}`;
        params.push(searchParams.date_range.end);
      }
      if (searchParams.zone) {
        sqlQuery += ` AND zone ILIKE $${paramIndex++}`;
        params.push(`%${searchParams.zone}%`);
      }
      if (searchParams.status) {
        sqlQuery += ` AND status = $${paramIndex++}`;
        params.push(searchParams.status);
      }
      if (searchParams.booking_id) {
        sqlQuery += ` AND booking_id ILIKE $${paramIndex++}`;
        params.push(`%${searchParams.booking_id}%`);
      }

      sqlQuery += ' ORDER BY booking_date DESC, start_time DESC LIMIT 50';

      const result = await pool.query(sqlQuery, params);

      res.json({
        ...searchParams,
        results: result.rows,
        count: result.rows.length
      });
    } else {
      res.json(searchParams);
    }
  } catch (error) {
    console.error('AI Search Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to process search' });
  }
});

// Get busy times for a date
app.get('/api/ai/busy-times', async (req, res) => {
  try {
    const date = req.query.date || new Date().toISOString().split('T')[0];

    const result = await pool.query(
      'SELECT start_time, end_time, zone FROM bookings WHERE booking_date = $1 AND status != \'cancelled\'',
      [date]
    );

    const analysis = await AIService.getCrowdAnalysis(result.rows, date);
    res.json(analysis);
  } catch (error) {
    console.error('Busy Times Error:', error);
    res.status(500).json({ success: false, error: 'SERVER_ERROR', message: 'Failed to get busy times' });
  }
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: 'NOT_FOUND', message: 'Endpoint not found' });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const isCorsError = err?.message === 'Not allowed by CORS';
  const status = isCorsError ? 403 : err?.status || 500;
  res.status(status).json({
    success: false,
    error: isCorsError ? 'FORBIDDEN' : 'SERVER_ERROR',
    message: isCorsError ? 'CORS blocked this request.' : err?.message || 'An unexpected error occurred.'
  });
});

// Start server
// Start server if not running in Vercel
if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  app.listen(PORT, () => {
    console.log(`
  Night Market Booking API Server
  ================================
  Server running on http://localhost:${PORT}

  Endpoints:
    POST   /api/bookings              - Create a new booking
    GET    /api/bookings              - List all bookings
    GET    /api/bookings/:id          - Get booking by ID
    PATCH  /api/bookings/:id/cancel   - Cancel a booking
    GET    /api/availability          - Check available time slots
    GET    /api/health                - Health check
  `);
  });
}

export default app;
