/**
 * Night Market AI Chat Widget
 * Floating chat assistant for booking help
 */

const AIChatWidget = {
  isOpen: false,
  messages: [],
  isLoading: false,

  // API base URL
  apiBase: window.location.hostname === 'localhost' ? 'http://localhost:3001/api' : '/api',

  // Initialize the chat widget
  init() {
    this.createWidget();
    this.attachEventListeners();
    this.loadChatHistory();
    this.restoreChatState();
  },

  // Save chat open state to sessionStorage
  saveChatState() {
    sessionStorage.setItem('nightmarket_chat_open', this.isOpen ? 'true' : 'false');
  },

  // Restore chat state after page reload
  restoreChatState() {
    const wasOpen = sessionStorage.getItem('nightmarket_chat_open') === 'true';
    if (wasOpen && !this.isOpen) {
      this.toggleChat();
    }
    // Clear the flag after restoring
    sessionStorage.removeItem('nightmarket_chat_open');
  },

  // Strip pricing/cost mentions from AI responses (this is a FREE service)
  stripPricing(message) {
    if (!message) return message;

    // First, strip markdown bold formatting to make pattern matching easier
    let cleaned = message.replace(/\*\*/g, '');

    // Replace common pricing patterns
    cleaned = cleaned
      // Remove dollar amounts like $20, $10.00, etc.
      .replace(/\$\d+(?:\.\d{2})?(?:\s*per\s*hour)?/gi, '')
      // Remove pricing lines like "- 30 minutes: $10" or "- 30 minutes:" (with or without price)
      .replace(/[-•]\s*\d+\s*minutes?:?\s*\$?\d*(?:\.\d{2})?\s*\n?/gi, '')
      // Remove "costs X" or "price is X" patterns
      .replace(/(?:costs?|price(?:d)?(?:\s+(?:is|at))?|charges?|fees?(?:\s+(?:is|of))?)\s*(?:is\s*)?\$\d+(?:\.\d{2})?(?:\s*per\s*hour)?/gi, '')
      // Remove "X per hour" patterns
      .replace(/\$\d+(?:\.\d{2})?\s*(?:per|\/)\s*hour/gi, '')
      // Remove "hourly rate" mentions
      .replace(/(?:hourly\s+)?rate\s*(?:is|of)?\s*\$\d+(?:\.\d{2})?/gi, '')
      // Clean up "No, this service is not free" type responses (handle various formats)
      .replace(/no,?\s*(?:this\s+)?(?:service\s+)?is\s+not\s+free\.?/gi, 'Yes, this is a FREE community bike sharing service!')
      .replace(/(?:this\s+)?(?:service\s+)?is\s+not\s+free\.?/gi, 'This is a FREE service!')
      .replace(/is\s+not\s+free/gi, 'is FREE')
      .replace(/not\s+free/gi, 'FREE')
      // Remove "We charge" patterns
      .replace(/we\s+charge\s*/gi, '')
      // Remove "fee covers/supports/helps" patterns and surrounding text
      .replace(/the\s+fee\s+(?:covers|supports|helps)\s*[^.]*\./gi, '')
      .replace(/(?:this|the)\s+fee\s+(?:supports?|helps?)\s*[^.]*\./gi, '')
      // Remove "price varies" patterns
      .replace(/the\s+price\s+varies\s*[^.]*[.:]/gi, '')
      .replace(/price\s+varies\s+based\s+on\s*[^.]*[.:]/gi, '')
      // Remove "for bike rentals" fragment when orphaned
      .replace(/\.?\s*for\s+bike\s+rentals\.?\s*(?:this\s+means:?)?/gi, '')
      // Remove "This means:" when orphaned
      .replace(/\.?\s*this\s+means:?\s*/gi, ' ')
      // Remove "with pricing based on duration" and similar
      .replace(/,?\s*with\s+pric(?:ing|es?)\s+based\s+on\s+duration\.?/gi, '.')
      // Remove "For example:" followed by nothing useful
      .replace(/for\s+example:\s*(?=Would|$)/gi, '')
      // Remove mentions of pricing/payment
      .replace(/(?:pricing|payment|cost|fee)s?\s+(?:is|are|will\s+be)\s+(?:based|calculated)\s+on\s+duration\.?/gi, '')
      // Remove orphaned punctuation and fragments
      .replace(/\.\s*\.\s*/g, '. ')
      .replace(/\s+\./g, '.')
      .replace(/:\s*\./g, '.')
      .replace(/!:\s*/g, '! ')
      .replace(/:\s*(?=[A-Z])/g, '. ')
      .replace(/:\s*$/g, '')
      // Clean up multiple spaces and newlines
      .replace(/\n\s*\n\s*\n/g, '\n\n')
      .replace(/  +/g, ' ')
      .trim();

    // If the message was mostly about pricing and is now empty/short, provide a helpful response
    if (cleaned.length < 50 || cleaned.match(/^\s*yes[,!]?\s*$/i)) {
      cleaned = "Yes! This is a FREE community bike sharing service. Would you like to book a ride?";
    }

    return cleaned;
  },

  // Create the chat widget HTML
  createWidget() {
    const widget = document.createElement('div');
    widget.id = 'ai-chat-widget';
    widget.innerHTML = `
      <!-- Chat Toggle Button -->
      <button id="ai-chat-toggle" class="fixed bottom-6 right-6 z-50 w-14 h-14 bg-brand-yellow hover:bg-[#EACE40] rounded-full shadow-lg shadow-brand-yellow/30 flex items-center justify-center transition-all duration-300 transform hover:scale-110 group">
        <span id="chat-icon-open" class="material-symbols-outlined text-black text-2xl">smart_toy</span>
        <span id="chat-icon-close" class="material-symbols-outlined text-black text-2xl hidden">close</span>
        <span class="absolute -top-1 -right-1 w-4 h-4 bg-green-500 rounded-full border-2 border-black animate-pulse"></span>
      </button>
      
      <!-- Chat Window -->
      <div id="ai-chat-window" class="fixed bottom-24 right-6 z-50 w-[380px] max-w-[calc(100vw-48px)] max-h-[calc(100vh-120px)] bg-surface-dark border border-white/10 rounded-2xl shadow-2xl overflow-hidden transform scale-0 opacity-0 origin-bottom-right transition-all duration-300 flex flex-col">
        <!-- Header -->
        <div class="bg-brand-yellow text-black p-4 flex items-center gap-3 shrink-0">
          <div class="w-10 h-10 bg-black/10 rounded-full flex items-center justify-center">
            <span class="material-symbols-outlined text-xl">smart_toy</span>
          </div>
          <div class="flex-1">
            <h3 class="font-bold text-sm">Night Market Assistant</h3>
            <p class="text-xs opacity-80">AI-powered booking help</p>
          </div>
          <button id="ai-chat-minimize" class="p-1 hover:bg-black/10 rounded-lg transition-colors">
            <span class="material-symbols-outlined">remove</span>
          </button>
        </div>
        
        <!-- Quick Actions -->
        <div class="p-3 border-b border-white/10 bg-white/5 shrink-0">
          <div class="flex gap-2 overflow-x-auto no-scrollbar">
            <button class="ai-quick-action shrink-0 px-3 py-1.5 bg-white/10 hover:bg-brand-yellow hover:text-black text-white text-xs font-medium rounded-full transition-colors" data-action="book">
              Book a ride
            </button>
            <button class="ai-quick-action shrink-0 px-3 py-1.5 bg-white/10 hover:bg-brand-yellow hover:text-black text-white text-xs font-medium rounded-full transition-colors" data-action="availability">
              Check availability
            </button>
            <button class="ai-quick-action shrink-0 px-3 py-1.5 bg-white/10 hover:bg-brand-yellow hover:text-black text-white text-xs font-medium rounded-full transition-colors" data-action="mybookings">
              My bookings
            </button>
            <button class="ai-quick-action shrink-0 px-3 py-1.5 bg-white/10 hover:bg-brand-yellow hover:text-black text-white text-xs font-medium rounded-full transition-colors" data-action="busy">
              Quiet times
            </button>
          </div>
        </div>
        
        <!-- Messages -->
        <div id="ai-chat-messages" class="flex-1 min-h-[200px] max-h-[350px] overflow-y-auto p-4 space-y-4 scroll-smooth">
          <!-- Welcome message -->
          <div class="flex gap-3">
            <div class="w-8 h-8 bg-brand-yellow rounded-full flex items-center justify-center shrink-0">
              <span class="material-symbols-outlined text-black text-sm">smart_toy</span>
            </div>
            <div class="flex-1">
              <div class="bg-white/10 rounded-2xl rounded-tl-none p-3 text-sm text-white">
                <p>Hey there! I'm your Night Market assistant. I can help you:</p>
                <ul class="mt-2 space-y-1 text-gray-300">
                  <li>Book bike rides</li>
                  <li>Check availability</li>
                  <li>Cancel or reschedule bookings</li>
                  <li>Find the best times to ride</li>
                </ul>
                <p class="mt-2">What would you like to do?</p>
              </div>
              <span class="text-[10px] text-gray-500 mt-1 block">Just now</span>
            </div>
          </div>
        </div>
        
        <!-- Input -->
        <div class="p-4 border-t border-white/10 bg-white/5 shrink-0">
          <form id="ai-chat-form" class="flex gap-2">
            <div class="flex-1 relative">
              <input 
                type="text" 
                id="ai-chat-input" 
                placeholder="Type your message..." 
                class="w-full bg-black border border-white/10 rounded-xl px-4 py-3 pr-10 text-sm text-white placeholder-gray-500 focus:border-brand-yellow focus:ring-1 focus:ring-brand-yellow outline-none transition-all"
                autocomplete="off"
              />
              <button type="button" id="ai-voice-btn" class="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-gray-500 hover:text-brand-yellow transition-colors" title="Voice input (coming soon)">
                <span class="material-symbols-outlined text-lg">mic</span>
              </button>
            </div>
            <button type="submit" id="ai-chat-send" class="w-11 h-11 bg-brand-yellow hover:bg-[#EACE40] rounded-xl flex items-center justify-center transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
              <span class="material-symbols-outlined text-black">send</span>
            </button>
          </form>
          <p class="text-[10px] text-gray-600 mt-2 text-center">Powered by AI. Responses may vary.</p>
        </div>
      </div>
    `;

    document.body.appendChild(widget);
  },

  // Attach event listeners
  attachEventListeners() {
    const toggle = document.getElementById('ai-chat-toggle');
    const minimize = document.getElementById('ai-chat-minimize');
    const form = document.getElementById('ai-chat-form');
    const quickActions = document.querySelectorAll('.ai-quick-action');

    toggle?.addEventListener('click', () => this.toggleChat());
    minimize?.addEventListener('click', () => this.toggleChat());
    form?.addEventListener('submit', (e) => this.handleSubmit(e));

    quickActions.forEach(btn => {
      btn.addEventListener('click', () => this.handleQuickAction(btn.dataset.action));
    });

    // Close on escape
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.isOpen) {
        this.toggleChat();
      }
    });
  },

  // Toggle chat window
  toggleChat() {
    this.isOpen = !this.isOpen;
    const window = document.getElementById('ai-chat-window');
    const iconOpen = document.getElementById('chat-icon-open');
    const iconClose = document.getElementById('chat-icon-close');

    if (this.isOpen) {
      window.classList.remove('scale-0', 'opacity-0');
      window.classList.add('scale-100', 'opacity-100');
      iconOpen.classList.add('hidden');
      iconClose.classList.remove('hidden');
      document.getElementById('ai-chat-input')?.focus();
    } else {
      window.classList.add('scale-0', 'opacity-0');
      window.classList.remove('scale-100', 'opacity-100');
      iconOpen.classList.remove('hidden');
      iconClose.classList.add('hidden');
    }
  },

  // Handle form submission
  async handleSubmit(e) {
    e.preventDefault();
    const input = document.getElementById('ai-chat-input');
    const message = input.value.trim();

    if (!message || this.isLoading) return;

    input.value = '';
    this.addMessage('user', message);
    await this.sendMessage(message);
  },

  // Handle quick action buttons
  handleQuickAction(action) {
    const messages = {
      book: "I'd like to book a bike ride",
      availability: "What times are available today?",
      mybookings: "Show me my upcoming bookings",
      busy: "When is the least busy time to ride?"
    };

    const message = messages[action];
    if (message) {
      this.addMessage('user', message);
      this.sendMessage(message);
    }
  },

  // Add message to chat
  addMessage(role, content, isLoading = false) {
    const container = document.getElementById('ai-chat-messages');
    const messageDiv = document.createElement('div');
    messageDiv.className = 'flex gap-3 animate-fadeIn';

    const time = new Date().toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit' });

    if (role === 'user') {
      messageDiv.innerHTML = `
        <div class="flex-1 flex flex-col items-end">
          <div class="bg-brand-yellow text-black rounded-2xl rounded-tr-none p-3 text-sm max-w-[85%]">
            ${this.escapeHtml(content)}
          </div>
          <span class="text-[10px] text-gray-500 mt-1">${time}</span>
        </div>
        <div class="w-8 h-8 bg-white/10 rounded-full flex items-center justify-center shrink-0">
          <span class="material-symbols-outlined text-white text-sm">person</span>
        </div>
      `;
    } else {
      messageDiv.innerHTML = `
        <div class="w-8 h-8 bg-brand-yellow rounded-full flex items-center justify-center shrink-0">
          <span class="material-symbols-outlined text-black text-sm">smart_toy</span>
        </div>
        <div class="flex-1">
          <div class="bg-white/10 rounded-2xl rounded-tl-none p-3 text-sm text-white max-w-[85%]">
            ${isLoading ? this.getLoadingHTML() : this.formatMessage(content)}
          </div>
          <span class="text-[10px] text-gray-500 mt-1 block">${time}</span>
        </div>
      `;

      if (isLoading) {
        messageDiv.id = 'ai-loading-message';
      }
    }

    container.appendChild(messageDiv);
    container.scrollTop = container.scrollHeight;

    // Store message in history
    if (!isLoading) {
      this.messages.push({ role, content });
      this.saveChatHistory();
    }

    return messageDiv;
  },

  // Loading HTML
  getLoadingHTML() {
    return `
      <div class="flex items-center gap-2">
        <div class="flex gap-1">
          <span class="w-2 h-2 bg-brand-yellow rounded-full animate-bounce" style="animation-delay: 0ms"></span>
          <span class="w-2 h-2 bg-brand-yellow rounded-full animate-bounce" style="animation-delay: 150ms"></span>
          <span class="w-2 h-2 bg-brand-yellow rounded-full animate-bounce" style="animation-delay: 300ms"></span>
        </div>
        <span class="text-gray-400">Thinking...</span>
      </div>
    `;
  },

  // Format AI message with markdown-like formatting
  formatMessage(content) {
    if (!content) return '';

    // Escape HTML first
    let formatted = this.escapeHtml(content);

    // Bold text
    formatted = formatted.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');

    // Booking IDs
    formatted = formatted.replace(/(BK-\d{4})/g, '<code class="bg-white/20 px-1 rounded">$1</code>');

    // Times
    formatted = formatted.replace(/(\d{1,2}:\d{2}\s*(AM|PM)?)/gi, '<span class="text-brand-yellow font-medium">$1</span>');

    // Line breaks
    formatted = formatted.replace(/\n/g, '<br>');

    // Lists
    formatted = formatted.replace(/^[-*]\s+(.+)$/gm, '<li class="ml-4">$1</li>');
    formatted = formatted.replace(/(<li.*<\/li>\n?)+/g, '<ul class="list-disc space-y-1 my-2">$&</ul>');

    return formatted;
  },

  // Escape HTML
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  // Send message to AI
  async sendMessage(userMessage) {
    if (this.isLoading) return;

    this.isLoading = true;
    const sendBtn = document.getElementById('ai-chat-send');
    sendBtn.disabled = true;

    // Add loading message
    this.addMessage('assistant', '', true);

    try {
      // Check if user is logged in
      if (typeof AuthAPI === 'undefined' || !AuthAPI.isLoggedIn()) {
        this.removeLoadingMessage();
        this.addMessage('assistant', "Please log in to use the AI assistant. I need to know who you are to help with bookings!");
        return;
      }

      // Build conversation history for context
      const conversationHistory = this.messages.slice(-10).map(m => ({
        role: m.role === 'user' ? 'user' : 'assistant',
        content: m.content
      }));

      // Add current message
      conversationHistory.push({ role: 'user', content: userMessage });

      let data;
      if (typeof AuthAPI !== 'undefined') {
        data = await AuthAPI.authFetch('/ai/chat', {
          method: 'POST',
          body: JSON.stringify({ messages: conversationHistory })
        });
      } else {
        const response = await fetch(`${this.apiBase}/ai/chat`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          credentials: 'include',
          body: JSON.stringify({ messages: conversationHistory })
        });
        data = await response.json();
      }

      this.removeLoadingMessage();

      if (data.success) {
        // Strip any pricing mentions - this is a FREE service
        const cleanedMessage = this.stripPricing(data.message);
        this.addMessage('assistant', cleanedMessage);

        // If a booking was made, refresh the page after a delay
        if (data.functionsCalled?.includes('create_booking')) {
          setTimeout(() => {
            if (window.location.pathname.includes('booking_schedule')) {
              // Save chat state before reload so it reopens
              this.saveChatState();
              window.location.reload();
            }
          }, 2000);
        }
      } else {
        this.addMessage('assistant', data.message || "Sorry, I couldn't process that request. Please try again.");
      }

    } catch (error) {
      console.error('Chat error:', error);
      this.removeLoadingMessage();
      this.addMessage('assistant', "Sorry, I'm having trouble connecting right now. Please try again in a moment.");
    } finally {
      this.isLoading = false;
      sendBtn.disabled = false;
    }
  },

  // Remove loading message
  removeLoadingMessage() {
    const loadingMsg = document.getElementById('ai-loading-message');
    if (loadingMsg) {
      loadingMsg.remove();
    }
  },

  // Save chat history to localStorage
  saveChatHistory() {
    // Keep last 20 messages
    const toSave = this.messages.slice(-20);
    localStorage.setItem('nightmarket_chat_history', JSON.stringify(toSave));
  },

  // Load chat history from localStorage
  loadChatHistory() {
    try {
      const saved = localStorage.getItem('nightmarket_chat_history');
      if (saved) {
        this.messages = JSON.parse(saved);
        // Don't restore messages on load to keep it fresh
        // Users can start fresh each session
      }
    } catch (e) {
      console.error('Error loading chat history:', e);
    }
  },

  // Clear chat history
  clearHistory() {
    this.messages = [];
    localStorage.removeItem('nightmarket_chat_history');
    const container = document.getElementById('ai-chat-messages');
    if (container) {
      container.innerHTML = `
        <div class="flex gap-3">
          <div class="w-8 h-8 bg-brand-yellow rounded-full flex items-center justify-center shrink-0">
            <span class="material-symbols-outlined text-black text-sm">smart_toy</span>
          </div>
          <div class="flex-1">
            <div class="bg-white/10 rounded-2xl rounded-tl-none p-3 text-sm text-white">
              <p>Chat cleared! How can I help you today?</p>
            </div>
            <span class="text-[10px] text-gray-500 mt-1 block">Just now</span>
          </div>
        </div>
      `;
    }
  }
};

// Add required styles
const chatStyles = document.createElement('style');
chatStyles.textContent = `
  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  
  .animate-fadeIn {
    animation: fadeIn 0.3s ease-out;
  }
  
  #ai-chat-messages::-webkit-scrollbar {
    width: 6px;
  }
  
  #ai-chat-messages::-webkit-scrollbar-track {
    background: transparent;
  }
  
  #ai-chat-messages::-webkit-scrollbar-thumb {
    background: rgba(255, 255, 255, 0.1);
    border-radius: 3px;
  }
  
  #ai-chat-messages::-webkit-scrollbar-thumb:hover {
    background: rgba(255, 255, 255, 0.2);
  }
  
  .no-scrollbar::-webkit-scrollbar {
    display: none;
  }
  
  .no-scrollbar {
    -ms-overflow-style: none;
    scrollbar-width: none;
  }
`;
document.head.appendChild(chatStyles);

// Initialize when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => AIChatWidget.init());
} else {
  AIChatWidget.init();
}

// Export for external access
window.AIChatWidget = AIChatWidget;
