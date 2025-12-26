# Night Market Booking Workflows

## Quick Start

1. **Run database migration**: Execute `database/001_create_bookings_table.sql` in PostgreSQL
2. **Import workflow**: Import `create_booking_workflow.json` into n8n
3. **Configure credentials**: Set up PostgreSQL, SMTP, and Slack credentials in n8n
4. **Activate workflow**: Toggle the workflow active in n8n
5. **Test**: Open `test/test_booking.html` in a browser or run `test/test_booking_webhook.sh`

## Project Structure

```
workflows/
├── create_booking_workflow.json    # Main n8n workflow
├── README.md                       # This documentation
├── database/
│   └── 001_create_bookings_table.sql  # PostgreSQL schema
└── test/
    ├── test_booking_webhook.sh     # CLI test script
    └── test_booking.html           # Browser-based tester
```

## Create Booking Workflow

**File:** `create_booking_workflow.json`

### Overview

This n8n workflow handles the complete booking creation process for the Night Market rider booking system.

### Workflow Flow

```
POST /webhook/create-booking
         │
         ▼
┌─────────────────────┐
│  Validate Booking   │──── Invalid ────▶ 400 Validation Error
│       Data          │
└─────────────────────┘
         │ Valid
         ▼
┌─────────────────────┐
│  Prepare Booking    │
│       Data          │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Check Time Slot    │──── Unavailable ─▶ 409 Slot Unavailable
│    Availability     │
└─────────────────────┘
         │ Available
         ▼
┌─────────────────────┐
│  Generate Booking   │
│        ID           │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│  Insert Booking     │
│    to Database      │
└─────────────────────┘
         │
         ▼
┌─────────────────────┐
│ Send Confirmation   │
│       Email         │
└─────────────────────┘
         │
         ▼
    201 Success Response


Error Handler (separate flow):
┌─────────────────────┐
│   Error Trigger     │────▶ Notify Slack #booking-alerts
└─────────────────────┘
```

### API Endpoint

**URL:** `POST /webhook/create-booking`

#### Request Body

```json
{
  "rider_id": "USR-001",
  "rider_name": "John Smith",
  "rider_email": "john@example.com",
  "booking_date": "2024-10-25",
  "start_time": "14:00",
  "duration_minutes": 60,
  "zone": "Main Paddock"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `rider_id` | string | Yes | Unique rider identifier |
| `rider_name` | string | Yes | Rider's full name |
| `rider_email` | string | Yes | Email for confirmation |
| `booking_date` | string | Yes | Date in YYYY-MM-DD format |
| `start_time` | string | Yes | Time in HH:MM format |
| `duration_minutes` | number | Yes | Duration (30, 45, 60, or 90) |
| `zone` | string | No | Riding zone (default: "Main Paddock") |

#### Response Examples

**Success (201):**
```json
{
  "success": true,
  "message": "Booking created successfully",
  "booking": {
    "booking_id": "BK-4821",
    "rider_id": "USR-001",
    "rider_name": "John Smith",
    "booking_date": "2024-10-25",
    "start_time": "14:00",
    "end_time": "15:00",
    "duration_minutes": 60,
    "zone": "Main Paddock",
    "total_cost": 20,
    "status": "confirmed",
    "created_at": "2024-10-24T10:30:00.000Z"
  },
  "confirmation_email_sent": true
}
```

**Validation Error (400):**
```json
{
  "success": false,
  "error": "VALIDATION_ERROR",
  "message": "Missing required fields...",
  "required_fields": {
    "rider_id": "string - Rider's unique identifier",
    "booking_date": "string - Date in YYYY-MM-DD format",
    "start_time": "string - Time in HH:MM format",
    "duration_minutes": "number - Duration in minutes"
  }
}
```

**Slot Unavailable (409):**
```json
{
  "success": false,
  "error": "SLOT_UNAVAILABLE",
  "message": "The requested time slot is not available...",
  "requested_slot": {
    "date": "2024-10-25",
    "start_time": "14:00",
    "end_time": "15:00",
    "zone": "Main Paddock"
  }
}
```

### Setup Instructions

#### 1. Import Workflow

1. Open your n8n instance
2. Go to **Workflows** > **Import from File**
3. Select `create_booking_workflow.json`

#### 2. Configure Credentials

Replace the placeholder credential IDs with your actual credentials:

| Credential | Node | Description |
|------------|------|-------------|
| `Night Market DB` | Check Availability, Insert Booking | PostgreSQL database connection |
| `Night Market SMTP` | Send Confirmation Email | SMTP server for emails |
| `Night Market Slack` | Error Notification | Slack workspace integration |

#### 3. Database Setup

Create the `bookings` table in PostgreSQL:

```sql
CREATE TABLE bookings (
  id SERIAL PRIMARY KEY,
  booking_id VARCHAR(10) UNIQUE NOT NULL,
  rider_id VARCHAR(50) NOT NULL,
  rider_name VARCHAR(100) NOT NULL,
  rider_email VARCHAR(255) NOT NULL,
  booking_date DATE NOT NULL,
  start_time TIME NOT NULL,
  end_time TIME NOT NULL,
  duration_minutes INTEGER NOT NULL,
  zone VARCHAR(50) DEFAULT 'Main Paddock',
  hourly_rate DECIMAL(10,2) DEFAULT 20.00,
  total_cost DECIMAL(10,2) NOT NULL,
  status VARCHAR(20) DEFAULT 'confirmed',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_bookings_date ON bookings(booking_date);
CREATE INDEX idx_bookings_rider ON bookings(rider_id);
CREATE INDEX idx_bookings_status ON bookings(status);
```

#### 4. Activate Workflow

1. Open the workflow in n8n
2. Click **Active** toggle in the top right
3. Test with a sample request

### Pricing Logic

- **Hourly Rate:** $20.00
- **Total Cost Formula:** `(duration_minutes / 60) * hourly_rate`

| Duration | Cost |
|----------|------|
| 30 min | $10.00 |
| 45 min | $15.00 |
| 60 min | $20.00 |
| 90 min | $30.00 |

### Error Handling

The workflow includes comprehensive error handling:

1. **Validation Errors** - Returns 400 with missing field details
2. **Availability Conflicts** - Returns 409 with slot information
3. **System Errors** - Caught by Error Trigger, notified to Slack

### Frontend Integration

Call this workflow from your booking form:

```javascript
async function createBooking(bookingData) {
  const response = await fetch('YOUR_N8N_URL/webhook/create-booking', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      rider_id: bookingData.riderId,
      rider_name: bookingData.riderName,
      rider_email: bookingData.riderEmail,
      booking_date: bookingData.date,
      start_time: bookingData.startTime,
      duration_minutes: bookingData.duration,
      zone: bookingData.zone
    })
  });

  const result = await response.json();

  if (result.success) {
    // Redirect to confirmation page
    window.location.href = `/booking_confirmation?id=${result.booking.booking_id}`;
  } else {
    // Show error message
    showError(result.message);
  }
}
```

### Customization

To modify pricing:
1. Edit the "Prepare Booking Data" node
2. Change `hourly_rate` value and `total_cost` formula

To add zones:
1. Update the database schema with zone options
2. Add zone selection to the frontend form

To change email template:
1. Edit the "Send Confirmation Email" node
2. Modify the HTML template in the `message` field
