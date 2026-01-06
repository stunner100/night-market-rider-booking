# 🌙 Night Market Rider Booking System

A modern, full-stack web application for managing bike rider bookings at the University of Ghana Night Market. Built with a sleek dark-themed UI and powered by AI for intelligent booking assistance.

![Night Market](night_market_400x400.jpg/night_market_400x400.jpg)

## ✨ Features

### 🚴 For Riders
- **Easy Booking** - Book bike rides with an intuitive calendar interface
- **Real-time Schedule** - View weekly schedules with visual time slots
- **My Bookings** - Manage, reschedule, or cancel your bookings
- **AI Assistant** - Get help booking rides through natural conversation
- **Notifications** - In-app notifications for booking confirmations and updates
- **Profile Settings** - Customize your notification preferences

### 👨‍💼 For Administrators
- **Dashboard Analytics** - Monitor active riders, bookings, and trends
- **AI Demand Insights** - AI-powered booking pattern analysis and predictions
- **Booking Management** - Approve, reject, or cancel bookings
- **Rider Management** - View and manage all registered riders
- **Data Export** - Export booking data to CSV

### 🤖 AI Features
- **Intelligent Chat Assistant** - Powered by Qwen AI for booking assistance
- **Demand Forecasting** - 7-day booking predictions
- **Pattern Analysis** - Identifies busiest days, hours, and zones
- **Smart Recommendations** - AI-driven operational suggestions

## 🛠️ Tech Stack

### Frontend
- **HTML5 / CSS3** - Semantic markup with modern styling
- **Tailwind CSS** - Utility-first CSS framework via CDN
- **JavaScript (ES6+)** - Vanilla JS for interactivity
- **Material Symbols** - Google's icon library

### Backend
- **Node.js** - JavaScript runtime
- **Express.js** - Web application framework
- **PostgreSQL** - Relational database (hosted on Supabase)
- **JWT** - JSON Web Tokens for authentication
- **bcrypt** - Password hashing

### AI Integration
- **Qwen (Alibaba Cloud)** - AI model for chat and analytics
- **OpenAI SDK** - Compatible API for Qwen integration

### Deployment
- **Vercel** - Frontend and serverless functions
- **Supabase** - PostgreSQL database hosting

## 📁 Project Structure

```
├── admin_dashboard/        # Admin control panel
├── api/                    # Vercel serverless functions
│   └── index.js           # Main API endpoints
├── booking_confirmation/   # Booking confirmation pages
├── booking_schedule/       # Calendar booking interface
├── css/                    # Global stylesheets
│   └── mobile.css         # Mobile-responsive styles
├── in-app_notifications/   # Notification center
├── js/                     # Shared JavaScript
│   ├── auth.js            # Authentication utilities
│   ├── ai-chat.js         # AI chat widget
│   ├── ai-recommendations.js
│   └── navigation.js      # Navigation component
├── my_bookings/           # User booking management
├── notification_settings/ # Notification preferences
├── profile_settings/      # User profile settings
├── server/                # Local development server
│   ├── index.js          # Express server
│   ├── ai-service.js     # AI integration service
│   └── migrations/       # Database migrations
├── support/               # Help & support page
├── user_login/           # Authentication pages
├── index.html            # Landing/login page
├── vercel.json           # Vercel configuration
└── package.json          # Dependencies
```

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn
- PostgreSQL database (or Supabase account)

### Environment Variables

Create a `.env` file in the root directory:

```env
# Database
DATABASE_URL=postgresql://user:password@host:port/database

# Authentication
JWT_SECRET=your-super-secret-jwt-key
JWT_FALLBACK_SECRET=optional-strong-fallback-secret

# Security / CORS
CORS_ORIGINS=https://night-market-rider-booking.vercel.app

# AI (Qwen via Alibaba Cloud)
DASHSCOPE_API_KEY=your-dashscope-api-key
```

Production requires `CORS_ORIGINS` and either `JWT_SECRET` or `JWT_FALLBACK_SECRET`.

## Release Notes

- Breaking: production deployments must set `CORS_ORIGINS` and provide `JWT_SECRET` or `JWT_FALLBACK_SECRET` for JWT authentication.

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/stunner100/night-market-rider-booking.git
   cd night-market-rider-booking
   ```

2. **Install dependencies**
   ```bash
   # Root dependencies
   npm install
   
   # Server dependencies
   cd server
   npm install
   cd ..
   ```

3. **Set up the database**
   
   Run the migration files in `server/migrations/` in order:
   ```sql
   -- 001_create_riders.sql
   -- 002_create_bookings.sql
   -- 003_create_notifications.sql
   -- 004_create_notification_settings.sql
   ```

4. **Start the development server**
   ```bash
   cd server
   npm start
   ```

5. **Open in browser**
   ```
   http://localhost:3000
   ```

### Deploy to Vercel

1. Install Vercel CLI
   ```bash
   npm i -g vercel
   ```

2. Deploy
   ```bash
   vercel --prod
   ```

3. Add environment variables in Vercel dashboard

## 📱 Pages & Routes

| Page | Path | Description |
|------|------|-------------|
| Login | `/` or `/user_login/registration/code.html` | User authentication |
| Schedule | `/booking_schedule/code.html` | Weekly calendar view |
| My Bookings | `/my_bookings/code.html` | User's booking list |
| Notifications | `/in-app_notifications/code.html` | Notification center |
| Settings | `/profile_settings/code.html` | Profile & preferences |
| Admin | `/admin_dashboard/code.html` | Admin control panel |

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register new rider |
| POST | `/api/auth/login` | Login & get JWT |
| GET | `/api/auth/me` | Get current user |

### Bookings
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/bookings` | List user's bookings |
| POST | `/api/bookings` | Create new booking |
| GET | `/api/bookings/week` | Get week's bookings |
| PATCH | `/api/bookings/:id/cancel` | Cancel booking |
| PATCH | `/api/bookings/:id/reschedule` | Reschedule booking |

### Admin
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/admin/stats` | Dashboard statistics |
| GET | `/api/admin/bookings` | All bookings (paginated) |
| PATCH | `/api/admin/bookings/:id/status` | Update booking status |
| DELETE | `/api/admin/bookings/clear-all` | Clear all bookings |

### AI
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/ai/chat` | AI chat assistant |
| GET | `/api/ai/analytics` | AI-powered analytics |

## 🎨 Design System

### Colors
- **Brand Yellow**: `#FFE979` - Primary accent
- **Brand Black**: `#000000` - Background
- **Brand Gray**: `#1A1A1A` - Cards/surfaces
- **Light Gray**: `#333333` - Borders
- **Text Muted**: `#9CA3AF` - Secondary text

### Typography
- **Font Family**: Plus Jakarta Sans
- **Icons**: Material Symbols Outlined

## 🔒 Security

- JWT-based authentication with httpOnly considerations
- Password hashing with bcrypt (10 salt rounds)
- Protected admin routes with role-based access
- SQL injection prevention via parameterized queries
- CORS configuration for API security

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Patrick Annor** ([@stunner100](https://github.com/stunner100))

---

Built with ❤️ for the University of Ghana Night Market community
