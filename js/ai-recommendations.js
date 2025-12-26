/**
 * Night Market AI Smart Recommendations
 * Shows personalized booking recommendations
 */

const AIRecommendations = {
  apiBase: window.location.hostname === 'localhost' ? 'http://localhost:3001/api' : '/api',
  recommendations: [],
  isLoading: false,
  
  // Initialize recommendations
  async init() {
    // Check if user is logged in
    const token = localStorage.getItem('nightmarket_token');
    if (!token) return;
    
    this.createWidget();
    await this.fetchRecommendations();
  },
  
  // Create the recommendations widget
  createWidget() {
    // Find the controls row in the schedule page
    const controlsRow = document.querySelector('.flex.flex-col-reverse.md\\:flex-row');
    if (!controlsRow) return;
    
    const widget = document.createElement('div');
    widget.id = 'ai-recommendations-widget';
    widget.className = 'w-full order-first md:order-none';
    widget.innerHTML = `
      <div class="bg-gradient-to-r from-brand-yellow/10 to-transparent border border-brand-yellow/20 rounded-2xl p-4 mb-4">
        <div class="flex items-center gap-2 mb-3">
          <span class="material-symbols-outlined text-brand-yellow text-lg">auto_awesome</span>
          <h3 class="text-white font-bold text-sm">AI Recommendations</h3>
          <button id="refresh-recommendations" class="ml-auto p-1 text-gray-400 hover:text-brand-yellow transition-colors" title="Refresh">
            <span class="material-symbols-outlined text-sm">refresh</span>
          </button>
        </div>
        <div id="recommendations-content" class="flex gap-2 overflow-x-auto no-scrollbar pb-1">
          <div class="flex items-center gap-2 text-gray-400 text-sm">
            <span class="animate-pulse">Loading recommendations...</span>
          </div>
        </div>
      </div>
    `;
    
    controlsRow.parentNode.insertBefore(widget, controlsRow);
    
    // Attach refresh handler
    document.getElementById('refresh-recommendations')?.addEventListener('click', () => {
      this.fetchRecommendations();
    });
  },
  
  // Fetch recommendations from API
  async fetchRecommendations() {
    const content = document.getElementById('recommendations-content');
    if (!content) return;
    
    this.isLoading = true;
    content.innerHTML = `
      <div class="flex items-center gap-2 text-gray-400 text-sm">
        <span class="material-symbols-outlined animate-spin text-sm">sync</span>
        <span>Getting personalized recommendations...</span>
      </div>
    `;
    
    try {
      const token = localStorage.getItem('nightmarket_token');
      const response = await fetch(`${this.apiBase}/ai/recommendations`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      
      const data = await response.json();
      
      if (data.success && data.recommendations?.length > 0) {
        this.recommendations = data.recommendations;
        this.renderRecommendations(data);
      } else {
        this.renderFallbackRecommendations(data);
      }
      
    } catch (error) {
      console.error('Recommendations error:', error);
      this.renderError();
    } finally {
      this.isLoading = false;
    }
  },
  
  // Render AI recommendations
  renderRecommendations(data) {
    const content = document.getElementById('recommendations-content');
    if (!content) return;
    
    let html = '';
    
    // Show insights if available
    if (data.insights) {
      html += `
        <div class="shrink-0 bg-white/5 border border-white/10 rounded-xl p-3 min-w-[160px]">
          <div class="text-[10px] text-gray-500 uppercase font-bold mb-1">Your Pattern</div>
          <div class="text-sm text-white font-medium">${data.insights.preferred_time || 'No history yet'}</div>
          <div class="text-[10px] text-gray-400 mt-1">${data.insights.booking_frequency || 'Start booking!'}</div>
        </div>
      `;
    }
    
    // Render each recommendation
    data.recommendations.slice(0, 4).forEach((rec, index) => {
      const date = new Date(rec.date);
      const dayName = date.toLocaleDateString('en-US', { weekday: 'short' });
      const dateStr = date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
      const time12 = this.formatTime(rec.time);
      const crowdClass = rec.crowd_level === 'low' ? 'text-green-400' : rec.crowd_level === 'high' ? 'text-red-400' : 'text-yellow-400';
      const crowdIcon = rec.crowd_level === 'low' ? 'trending_down' : rec.crowd_level === 'high' ? 'trending_up' : 'remove';
      
      html += `
        <button class="shrink-0 bg-black hover:bg-white/10 border border-white/10 hover:border-brand-yellow/50 rounded-xl p-3 min-w-[140px] text-left transition-all group recommendation-card" 
                data-date="${rec.date}" data-time="${rec.time}" data-zone="${rec.zone}">
          <div class="flex items-center gap-1 mb-1">
            <span class="text-[10px] text-brand-yellow font-bold uppercase">${dayName}</span>
            <span class="text-[10px] text-gray-500">${dateStr}</span>
          </div>
          <div class="text-white font-bold text-sm group-hover:text-brand-yellow transition-colors">${time12}</div>
          <div class="flex items-center gap-1 mt-1">
            <span class="material-symbols-outlined ${crowdClass} text-xs">${crowdIcon}</span>
            <span class="text-[10px] ${crowdClass} capitalize">${rec.crowd_level} crowd</span>
          </div>
          <div class="text-[10px] text-gray-500 mt-1 truncate">${rec.zone}</div>
          <div class="text-[10px] text-gray-600 mt-1 italic line-clamp-1">${rec.reason || ''}</div>
        </button>
      `;
    });
    
    content.innerHTML = html;
    
    // Add click handlers to recommendation cards
    content.querySelectorAll('.recommendation-card').forEach(card => {
      card.addEventListener('click', () => {
        this.handleRecommendationClick(card.dataset);
      });
    });
  },
  
  // Render fallback when no AI recommendations available
  renderFallbackRecommendations(data) {
    const content = document.getElementById('recommendations-content');
    if (!content) return;
    
    // Show basic recommendations based on available data
    let html = '';
    
    if (data.user_history_count === 0) {
      html = `
        <div class="shrink-0 bg-white/5 border border-white/10 rounded-xl p-3 min-w-[200px]">
          <div class="flex items-center gap-2 text-brand-yellow mb-1">
            <span class="material-symbols-outlined text-sm">lightbulb</span>
            <span class="text-xs font-bold">New Here?</span>
          </div>
          <div class="text-sm text-white">Book your first ride to get personalized recommendations!</div>
        </div>
      `;
    } else if (data.preferred_time) {
      html = `
        <div class="shrink-0 bg-white/5 border border-white/10 rounded-xl p-3 min-w-[160px]">
          <div class="text-[10px] text-gray-500 uppercase font-bold mb-1">Your Favorite Time</div>
          <div class="text-sm text-white font-medium">${this.formatTime(data.preferred_time)}</div>
          <div class="text-[10px] text-gray-400 mt-1">Based on ${data.user_history_count} bookings</div>
        </div>
      `;
    }
    
    // Add generic quiet times suggestion
    html += `
      <button class="shrink-0 bg-black hover:bg-white/10 border border-white/10 hover:border-brand-yellow/50 rounded-xl p-3 min-w-[140px] text-left transition-all group"
              onclick="AIChatWidget.toggleChat(); AIChatWidget.handleQuickAction('busy');">
        <div class="flex items-center gap-1 mb-1">
          <span class="material-symbols-outlined text-green-400 text-sm">schedule</span>
          <span class="text-[10px] text-green-400 font-bold">QUIET TIMES</span>
        </div>
        <div class="text-white text-sm group-hover:text-brand-yellow transition-colors">Ask AI for best times</div>
        <div class="text-[10px] text-gray-500 mt-1">Low crowd guaranteed</div>
      </button>
    `;
    
    content.innerHTML = html;
  },
  
  // Render error state
  renderError() {
    const content = document.getElementById('recommendations-content');
    if (!content) return;
    
    content.innerHTML = `
      <div class="flex items-center gap-2 text-gray-400 text-sm">
        <span class="material-symbols-outlined text-sm">error</span>
        <span>Couldn't load recommendations. </span>
        <button class="text-brand-yellow hover:underline" onclick="AIRecommendations.fetchRecommendations()">Try again</button>
      </div>
    `;
  },
  
  // Handle recommendation card click - open booking modal
  handleRecommendationClick(data) {
    const { date, time, zone } = data;
    
    // Try to use the existing booking modal
    const bookingDateInput = document.getElementById('bookingDate');
    const startTimeInput = document.getElementById('startTime');
    const zoneSelect = document.getElementById('zoneSelect');
    const modal = document.getElementById('bookingModal');
    
    if (bookingDateInput && startTimeInput && modal) {
      bookingDateInput.value = date;
      startTimeInput.value = time;
      
      // Calculate end time (1 hour later by default)
      const endTimeInput = document.getElementById('endTime');
      if (endTimeInput) {
        const [h, m] = time.split(':').map(Number);
        const endHour = h + 1;
        endTimeInput.value = `${String(endHour).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
      }
      
      if (zoneSelect && zone) {
        zoneSelect.value = zone;
      }
      
      modal.classList.remove('hidden');
      modal.classList.add('flex');
    }
  },
  
  // Format time to 12-hour format
  formatTime(time24) {
    if (!time24) return '';
    const [hours, minutes] = time24.split(':').map(Number);
    const period = hours >= 12 ? 'PM' : 'AM';
    const hours12 = hours % 12 || 12;
    return `${hours12}:${String(minutes).padStart(2, '0')} ${period}`;
  }
};

// Initialize on DOM ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => AIRecommendations.init());
} else {
  AIRecommendations.init();
}

window.AIRecommendations = AIRecommendations;
