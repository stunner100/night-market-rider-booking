/**
 * Night Market Booking API Client
 * Handles communication with the n8n booking workflow
 */

const BookingAPI = {
  // Use relative URL for production, localhost for development
  webhookUrl: window.location.hostname === 'localhost' ? 'http://localhost:3001/api/bookings' : '/api/bookings',

  /**
   * Set the webhook URL (call this on app initialization)
   * @param {string} url - The n8n webhook URL
   */
  setWebhookUrl(url) {
    this.webhookUrl = url;
  },

  /**
   * Create a new booking
   * @param {Object} bookingData - The booking details
   * @param {string} bookingData.rider_id - Rider's unique identifier
   * @param {string} bookingData.rider_name - Rider's full name
   * @param {string} bookingData.rider_email - Rider's email address
   * @param {string} bookingData.booking_date - Date in YYYY-MM-DD format
   * @param {string} bookingData.start_time - Time in HH:MM format
   * @param {number} bookingData.duration_minutes - Duration (30, 45, 60, or 90)
   * @param {string} [bookingData.zone] - Riding zone (optional)
   * @returns {Promise<Object>} - API response
   */
  async createBooking(bookingData) {
    try {
      const response = await fetch(this.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(bookingData)
      });

      const data = await response.json();

      if (!response.ok) {
        return {
          success: false,
          status: response.status,
          error: data.error || 'UNKNOWN_ERROR',
          message: data.message || 'An error occurred while creating the booking.',
          data: data
        };
      }

      return {
        success: true,
        status: response.status,
        booking: data.booking,
        message: data.message
      };
    } catch (error) {
      return {
        success: false,
        status: 0,
        error: 'NETWORK_ERROR',
        message: 'Unable to connect to the booking service. Please check your connection and try again.',
        originalError: error.message
      };
    }
  },

  /**
   * Calculate total cost based on duration
   * @param {number} durationMinutes - Duration in minutes
   * @param {number} [hourlyRate=20] - Hourly rate in dollars
   * @returns {number} - Total cost
   */
  calculateCost(durationMinutes, hourlyRate = 20) {
    return (durationMinutes / 60) * hourlyRate;
  },

  /**
   * Format time string to display format
   * @param {string} time - Time in HH:MM format
   * @returns {string} - Formatted time (e.g., "2:30 PM")
   */
  formatTime(time) {
    const [hours, minutes] = time.split(':').map(Number);
    const period = hours >= 12 ? 'PM' : 'AM';
    const displayHours = hours % 12 || 12;
    return `${displayHours}:${minutes.toString().padStart(2, '0')} ${period}`;
  },

  /**
   * Calculate end time based on start time and duration
   * @param {string} startTime - Start time in HH:MM format
   * @param {number} durationMinutes - Duration in minutes
   * @returns {string} - End time in HH:MM format
   */
  calculateEndTime(startTime, durationMinutes) {
    const [hours, minutes] = startTime.split(':').map(Number);
    const totalMinutes = hours * 60 + minutes + durationMinutes;
    const endHours = Math.floor(totalMinutes / 60) % 24;
    const endMinutes = totalMinutes % 60;
    return `${endHours.toString().padStart(2, '0')}:${endMinutes.toString().padStart(2, '0')}`;
  },

  /**
   * Format date for API
   * @param {Date} date - Date object
   * @returns {string} - Date in YYYY-MM-DD format
   */
  formatDateForAPI(date) {
    return date.toISOString().split('T')[0];
  },

  /**
   * Format date for display
   * @param {string} dateStr - Date in YYYY-MM-DD format
   * @returns {string} - Formatted date (e.g., "Wednesday, Oct 18")
   */
  formatDateForDisplay(dateStr) {
    const date = new Date(dateStr + 'T00:00:00');
    const options = { weekday: 'long', month: 'short', day: 'numeric' };
    return date.toLocaleDateString('en-US', options);
  }
};

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BookingAPI;
}
