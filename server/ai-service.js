/**
 * Night Market AI Service
 * Handles all AI-powered features using Groq (Llama models)
 */

import OpenAI from 'openai';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Initialize Groq client via OpenAI-compatible API
const openai = new OpenAI({
  apiKey: process.env.GROQ_API_KEY,
  baseURL: 'https://api.groq.com/openai/v1'
});

// Model configuration
const PRIMARY_MODEL = 'llama-3.3-70b-versatile';  // Main model for chatbot
const FAST_MODEL = 'llama-3.1-8b-instant';         // Fast model for simple tasks

// System prompts for different AI features
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
- Duration options: 30, 45, 60, 90, 120, 180, 240 minutes
- This is a FREE community bike sharing service - no payment required

IMPORTANT - Streamlined Booking Flow:
- Make booking as EASY as possible with minimal questions
- If user says "book a ride" without details, use smart defaults:
  * Default duration: 60 minutes
  * Default zone: Main Campus
  * Default date: today (if time allows) or tomorrow
  * Default time: next available hour slot
- Only ask for date/time if user doesn't specify
- Skip asking about duration and zone unless user wants to customize
- NEVER mention pricing or costs - this is a free service
- After getting date and time, book immediately without extra confirmation
- Be proactive: "I'll book you for [time] at Main Campus for 1 hour - done!"

Guidelines:
- Be friendly, ultra-concise, and action-oriented
- Prioritize speed - book first, details later
- Use 12-hour format for display (10:00 AM, not 10:00)
- Only ask clarifying questions if absolutely necessary

Current date and time will be provided in each request.`;

const RECOMMENDATION_SYSTEM_PROMPT = `You are an AI that analyzes booking patterns and provides personalized recommendations.
Based on user history and crowd patterns, suggest optimal booking times.
Consider: user's preferred times, zone preferences, crowd levels, and weather if available.
Respond in JSON format with recommendations array.`;

const NOTIFICATION_SYSTEM_PROMPT = `You are an AI that generates personalized, context-aware notifications for bike booking users.
Create friendly, engaging notifications that are:
- Concise (max 2 sentences)
- Actionable when appropriate
- Personalized based on user context
- Relevant to the situation (reminder, weather, promotion, etc.)`;

const ANALYTICS_SYSTEM_PROMPT = `You are an AI analyst for a bike booking service.
Analyze booking data and provide insights about:
- Demand patterns (busy/quiet times)
- Zone popularity
- User behavior trends
- Predictions for upcoming periods
Respond with actionable insights in JSON format.`;

// OpenAI Function definitions for the chatbot
const BOOKING_FUNCTIONS = [
  {
    type: "function",
    function: {
      name: "check_availability",
      description: "Check available time slots for a specific date",
      parameters: {
        type: "object",
        properties: {
          date: {
            type: "string",
            description: "The date to check in YYYY-MM-DD format"
          },
          zone: {
            type: "string",
            description: "The riding zone (optional)",
            enum: ["Main Campus", "Diaspora", "Night Market", "Pent & Beyond"]
          }
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
          booking_date: {
            type: "string",
            description: "The booking date in YYYY-MM-DD format"
          },
          start_time: {
            type: "string",
            description: "The start time in HH:MM format (24-hour)"
          },
          duration_minutes: {
            type: "number",
            description: "Duration in minutes (30, 45, 60, 90, 120, 180, or 240)"
          },
          zone: {
            type: "string",
            description: "The riding zone",
            enum: ["Main Campus", "Diaspora", "Night Market", "Pent & Beyond"]
          }
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
          status: {
            type: "string",
            description: "Filter by booking status",
            enum: ["upcoming", "all", "cancelled", "completed"]
          }
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
          booking_id: {
            type: "string",
            description: "The booking ID to cancel (e.g., BK-1234)"
          }
        },
        required: ["booking_id"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "reschedule_booking",
      description: "Reschedule an existing booking to a new date/time",
      parameters: {
        type: "object",
        properties: {
          booking_id: {
            type: "string",
            description: "The booking ID to reschedule"
          },
          new_date: {
            type: "string",
            description: "The new date in YYYY-MM-DD format"
          },
          new_time: {
            type: "string",
            description: "The new start time in HH:MM format"
          }
        },
        required: ["booking_id", "new_date", "new_time"]
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_recommendations",
      description: "Get personalized booking time recommendations based on user history and crowd patterns",
      parameters: {
        type: "object",
        properties: {
          preferred_date: {
            type: "string",
            description: "Preferred date (optional) in YYYY-MM-DD format"
          }
        },
        required: []
      }
    }
  },
  {
    type: "function",
    function: {
      name: "get_busy_times",
      description: "Get information about busy and quiet times for booking",
      parameters: {
        type: "object",
        properties: {
          date: {
            type: "string",
            description: "The date to check in YYYY-MM-DD format (optional)"
          }
        },
        required: []
      }
    }
  }
];

/**
 * AI Chatbot - Main conversation handler
 */
export async function chatWithAssistant(messages, userContext, functionExecutor) {
  try {
    // Add current context to system message
    const currentTime = new Date().toISOString();
    const systemMessage = {
      role: "system",
      content: `${CHATBOT_SYSTEM_PROMPT}

Current Context:
- Current date/time: ${currentTime}
- User: ${userContext.rider_name} (ID: ${userContext.rider_id})
- User email: ${userContext.rider_email || 'Not provided'}

Remember to be helpful and confirm actions before executing them.`
    };

    const response = await openai.chat.completions.create({
      model: PRIMARY_MODEL,
      messages: [systemMessage, ...messages],
      tools: BOOKING_FUNCTIONS,
      tool_choice: "auto",
      temperature: 0.7,
      max_tokens: 1000
    });

    const assistantMessage = response.choices[0].message;

    // Check if the model wants to call functions
    if (assistantMessage.tool_calls && assistantMessage.tool_calls.length > 0) {
      const toolResults = [];

      for (const toolCall of assistantMessage.tool_calls) {
        const functionName = toolCall.function.name;
        const functionArgs = JSON.parse(toolCall.function.arguments);

        // Execute the function using the provided executor
        const result = await functionExecutor(functionName, functionArgs, userContext);

        toolResults.push({
          tool_call_id: toolCall.id,
          role: "tool",
          content: JSON.stringify(result)
        });
      }

      // Get final response after function execution
      const finalResponse = await openai.chat.completions.create({
        model: PRIMARY_MODEL,
        messages: [
          systemMessage,
          ...messages,
          assistantMessage,
          ...toolResults
        ],
        temperature: 0.7,
        max_tokens: 1000
      });

      return {
        success: true,
        message: finalResponse.choices[0].message.content,
        functionsCalled: assistantMessage.tool_calls.map(tc => tc.function.name)
      };
    }

    return {
      success: true,
      message: assistantMessage.content,
      functionsCalled: []
    };

  } catch (error) {
    console.error('AI Chat Error:', error);
    return {
      success: false,
      message: "I'm sorry, I encountered an error. Please try again or contact support.",
      error: error.message
    };
  }
}

/**
 * Smart Booking Recommendations
 */
export async function getSmartRecommendations(userHistory, crowdData, preferences) {
  try {
    const prompt = `Analyze this user's booking history and provide personalized recommendations.

User Booking History:
${JSON.stringify(userHistory, null, 2)}

Recent Crowd Patterns (bookings per hour):
${JSON.stringify(crowdData, null, 2)}

User Preferences:
${JSON.stringify(preferences, null, 2)}

Provide 3-5 recommended time slots for the next 7 days.
Consider: user's preferred times, less crowded periods, and zone preferences.

Respond in this JSON format:
{
  "recommendations": [
    {
      "date": "YYYY-MM-DD",
      "time": "HH:MM",
      "zone": "Zone Name",
      "reason": "Short explanation",
      "crowd_level": "low|medium|high",
      "confidence": 0.0-1.0
    }
  ],
  "insights": {
    "preferred_time": "Morning/Afternoon/Evening",
    "preferred_zone": "Zone name",
    "booking_frequency": "X times per week/month"
  }
}`;

    const response = await openai.chat.completions.create({
      model: PRIMARY_MODEL,
      messages: [
        { role: "system", content: RECOMMENDATION_SYSTEM_PROMPT },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" },
      temperature: 0.5,
      max_tokens: 1000
    });

    const result = JSON.parse(response.choices[0].message.content);
    return {
      success: true,
      ...result
    };

  } catch (error) {
    console.error('Recommendation Error:', error);
    return {
      success: false,
      recommendations: [],
      error: error.message
    };
  }
}

/**
 * Demand Prediction & Analytics
 */
export async function analyzeDemandPatterns(historicalData, upcomingEvents = []) {
  try {
    const prompt = `Analyze this booking data and provide demand predictions and insights.

Historical Booking Data (last 30 days):
${JSON.stringify(historicalData, null, 2)}

Upcoming Events/Factors:
${JSON.stringify(upcomingEvents, null, 2)}

Provide analysis in this JSON format:
{
  "predictions": {
    "next_7_days": [
      {
        "date": "YYYY-MM-DD",
        "predicted_bookings": number,
        "peak_hours": ["HH:MM", "HH:MM"],
        "quiet_hours": ["HH:MM", "HH:MM"],
        "confidence": 0.0-1.0
      }
    ]
  },
  "patterns": {
    "busiest_day": "Day of week",
    "busiest_hour": "HH:MM",
    "quietest_day": "Day of week",
    "quietest_hour": "HH:MM",
    "average_daily_bookings": number,
    "weekend_vs_weekday_ratio": number
  },
  "zone_analysis": {
    "most_popular": "Zone name",
    "least_popular": "Zone name",
    "zone_distribution": {}
  },
  "recommendations": [
    "Actionable recommendation for admin"
  ],
  "alerts": [
    {
      "type": "high_demand|low_capacity|trend",
      "message": "Alert message",
      "date": "YYYY-MM-DD",
      "severity": "low|medium|high"
    }
  ]
}`;

    const response = await openai.chat.completions.create({
      model: PRIMARY_MODEL,
      messages: [
        { role: "system", content: ANALYTICS_SYSTEM_PROMPT },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" },
      temperature: 0.3,
      max_tokens: 2000
    });

    const result = JSON.parse(response.choices[0].message.content);
    return {
      success: true,
      ...result,
      generated_at: new Date().toISOString()
    };

  } catch (error) {
    console.error('Analytics Error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * AI-Generated Personalized Notifications
 */
export async function generateNotification(type, context) {
  try {
    let prompt = '';

    switch (type) {
      case 'booking_reminder':
        prompt = `Generate a friendly reminder notification for this upcoming booking:
Booking: ${context.booking_id}
Date: ${context.booking_date}
Time: ${context.start_time} - ${context.end_time}
Zone: ${context.zone}
User Name: ${context.rider_name}
Time until booking: ${context.time_until}`;
        break;

      case 'weather_alert':
        prompt = `Generate a weather-aware notification for a user with an upcoming booking:
Weather: ${context.weather}
Booking Date: ${context.booking_date}
User Name: ${context.rider_name}
Suggest rescheduling if weather is bad, or encourage if weather is good.`;
        break;

      case 'personalized_promotion':
        prompt = `Generate a personalized promotion notification:
User Name: ${context.rider_name}
Last Booking: ${context.last_booking_date}
Days Since Last Ride: ${context.days_inactive}
Preferred Zone: ${context.preferred_zone}
Preferred Time: ${context.preferred_time}
Current Promotion: ${context.promotion || 'None'}`;
        break;

      case 'slot_available':
        prompt = `Generate a notification that a previously full slot is now available:
Date: ${context.date}
Time: ${context.time}
Zone: ${context.zone}
User Name: ${context.rider_name}
User had previously searched for this slot.`;
        break;

      case 'weekly_summary':
        prompt = `Generate a weekly summary notification:
User Name: ${context.rider_name}
Rides This Week: ${context.rides_count}
Total Hours: ${context.total_hours}
Favorite Zone: ${context.favorite_zone}
Upcoming Bookings: ${context.upcoming_count}`;
        break;

      default:
        prompt = `Generate a notification: ${JSON.stringify(context)}`;
    }

    const response = await openai.chat.completions.create({
      model: FAST_MODEL,
      messages: [
        { role: "system", content: NOTIFICATION_SYSTEM_PROMPT },
        { role: "user", content: prompt }
      ],
      temperature: 0.8,
      max_tokens: 200
    });

    const notificationText = response.choices[0].message.content;

    // Generate a title as well
    const titleResponse = await openai.chat.completions.create({
      model: FAST_MODEL,
      messages: [
        { role: "system", content: "Generate a short, catchy title (max 5 words) for this notification. Respond with just the title." },
        { role: "user", content: notificationText }
      ],
      temperature: 0.8,
      max_tokens: 20
    });

    return {
      success: true,
      title: titleResponse.choices[0].message.content.trim(),
      message: notificationText.trim(),
      type: type,
      generated_at: new Date().toISOString()
    };

  } catch (error) {
    console.error('Notification Generation Error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Natural Language Search for bookings
 */
export async function naturalLanguageSearch(query, context) {
  try {
    const prompt = `Parse this natural language search query for a booking system and extract search parameters.

Query: "${query}"

Current Date: ${new Date().toISOString().split('T')[0]}
User Context: ${JSON.stringify(context)}

Return JSON with extracted search parameters:
{
  "date_range": {
    "start": "YYYY-MM-DD or null",
    "end": "YYYY-MM-DD or null"
  },
  "time_range": {
    "start": "HH:MM or null",
    "end": "HH:MM or null"
  },
  "zone": "zone name or null",
  "rider_name": "name or null",
  "booking_id": "ID or null",
  "status": "status or null",
  "sort_by": "date|time|zone or null",
  "intent": "search|question|action",
  "response_type": "list|count|summary"
}`;

    const response = await openai.chat.completions.create({
      model: FAST_MODEL,
      messages: [
        { role: "system", content: "You are a search query parser. Extract structured parameters from natural language queries. Always respond with valid JSON." },
        { role: "user", content: prompt }
      ],
      response_format: { type: "json_object" },
      temperature: 0.2,
      max_tokens: 300
    });

    const searchParams = JSON.parse(response.choices[0].message.content);
    return {
      success: true,
      ...searchParams,
      original_query: query
    };

  } catch (error) {
    console.error('Search Parse Error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

/**
 * Get crowd level analysis for a specific time
 */
export async function getCrowdAnalysis(bookingsData, targetDate) {
  try {
    // Calculate crowd levels per hour
    const hourlyBookings = {};
    for (let hour = 8; hour < 22; hour++) {
      hourlyBookings[`${String(hour).padStart(2, '0')}:00`] = 0;
    }

    bookingsData.forEach(booking => {
      const hour = booking.start_time.split(':')[0];
      const key = `${hour}:00`;
      if (hourlyBookings[key] !== undefined) {
        hourlyBookings[key]++;
      }
    });

    // Find least and most busy times
    const entries = Object.entries(hourlyBookings);
    const sorted = entries.sort((a, b) => a[1] - b[1]);

    return {
      success: true,
      date: targetDate,
      hourly_bookings: hourlyBookings,
      least_busy: sorted.slice(0, 3).map(([time, count]) => ({ time, count, level: 'low' })),
      most_busy: sorted.slice(-3).reverse().map(([time, count]) => ({ time, count, level: 'high' })),
      total_bookings: bookingsData.length,
      average_per_hour: Math.round(bookingsData.length / 14 * 10) / 10
    };

  } catch (error) {
    console.error('Crowd Analysis Error:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

export default {
  chatWithAssistant,
  getSmartRecommendations,
  analyzeDemandPatterns,
  generateNotification,
  naturalLanguageSearch,
  getCrowdAnalysis
};
