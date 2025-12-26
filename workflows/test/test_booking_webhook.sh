#!/bin/bash

# Night Market - Booking Webhook Test Script
# Usage: ./test_booking_webhook.sh [n8n_webhook_url]

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default webhook URL (update this after importing workflow)
WEBHOOK_URL="${1:-http://localhost:5678/webhook/create-booking}"

echo "=============================================="
echo "  Night Market - Booking Webhook Tests"
echo "=============================================="
echo ""
echo "Webhook URL: $WEBHOOK_URL"
echo ""

# Test 1: Successful booking
echo -e "${YELLOW}Test 1: Create Valid Booking${NC}"
echo "-------------------------------------------"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "rider_id": "USR-TEST-001",
    "rider_name": "John Smith",
    "rider_email": "john.smith@example.com",
    "booking_date": "2024-12-25",
    "start_time": "14:00",
    "duration_minutes": 60,
    "zone": "Main Paddock"
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "201" ]; then
  echo -e "${GREEN}PASS${NC} - Status: $HTTP_CODE"
  echo "Response: $BODY" | jq . 2>/dev/null || echo "$BODY"
else
  echo -e "${RED}FAIL${NC} - Status: $HTTP_CODE"
  echo "Response: $BODY"
fi
echo ""

# Test 2: Missing required fields
echo -e "${YELLOW}Test 2: Missing Required Fields${NC}"
echo "-------------------------------------------"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "rider_name": "Jane Doe"
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}PASS${NC} - Status: $HTTP_CODE (Expected validation error)"
  echo "Response: $BODY" | jq . 2>/dev/null || echo "$BODY"
else
  echo -e "${RED}FAIL${NC} - Status: $HTTP_CODE (Expected 400)"
  echo "Response: $BODY"
fi
echo ""

# Test 3: Invalid duration
echo -e "${YELLOW}Test 3: Invalid Duration (0 minutes)${NC}"
echo "-------------------------------------------"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "rider_id": "USR-TEST-002",
    "rider_name": "Invalid Duration",
    "rider_email": "test@example.com",
    "booking_date": "2024-12-25",
    "start_time": "10:00",
    "duration_minutes": 0
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "400" ]; then
  echo -e "${GREEN}PASS${NC} - Status: $HTTP_CODE (Expected validation error)"
  echo "Response: $BODY" | jq . 2>/dev/null || echo "$BODY"
else
  echo -e "${RED}FAIL${NC} - Status: $HTTP_CODE (Expected 400)"
  echo "Response: $BODY"
fi
echo ""

# Test 4: Different zone booking
echo -e "${YELLOW}Test 4: Booking Different Zone${NC}"
echo "-------------------------------------------"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "rider_id": "USR-TEST-003",
    "rider_name": "Alice Johnson",
    "rider_email": "alice@example.com",
    "booking_date": "2024-12-26",
    "start_time": "09:00",
    "duration_minutes": 90,
    "zone": "Zone A"
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "201" ]; then
  echo -e "${GREEN}PASS${NC} - Status: $HTTP_CODE"
  echo "Response: $BODY" | jq . 2>/dev/null || echo "$BODY"
else
  echo -e "${RED}FAIL${NC} - Status: $HTTP_CODE"
  echo "Response: $BODY"
fi
echo ""

# Test 5: Conflicting time slot (same zone, overlapping time)
echo -e "${YELLOW}Test 5: Conflicting Time Slot${NC}"
echo "-------------------------------------------"
echo "Note: This test expects 409 if Test 1 booking exists"

RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{
    "rider_id": "USR-TEST-004",
    "rider_name": "Bob Wilson",
    "rider_email": "bob@example.com",
    "booking_date": "2024-12-25",
    "start_time": "14:30",
    "duration_minutes": 60,
    "zone": "Main Paddock"
  }')

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" = "409" ]; then
  echo -e "${GREEN}PASS${NC} - Status: $HTTP_CODE (Expected conflict)"
  echo "Response: $BODY" | jq . 2>/dev/null || echo "$BODY"
elif [ "$HTTP_CODE" = "201" ]; then
  echo -e "${YELLOW}INFO${NC} - Status: $HTTP_CODE (No conflict - Test 1 may not exist)"
  echo "Response: $BODY" | jq . 2>/dev/null || echo "$BODY"
else
  echo -e "${RED}FAIL${NC} - Status: $HTTP_CODE"
  echo "Response: $BODY"
fi
echo ""

echo "=============================================="
echo "  Tests Complete"
echo "=============================================="
