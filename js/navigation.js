/**
 * Night Market - Shared Navigation Component
 * Include this script in all pages to get a consistent navigation bar
 * Requires auth.js to be loaded first for authentication features
 */

(function () {
  // Navigation items configuration
  const navItems = [
    { name: 'Schedule', href: '/booking_schedule/code.html', icon: 'calendar_month' },
    { name: 'My Bookings', href: '/my_bookings/code.html', icon: 'receipt_long' },
    { name: 'Notifications', href: '/in-app_notifications/code.html', icon: 'notifications' },
    { name: 'Settings', href: '/notification_settings/code.html', icon: 'settings' }
  ];

  // Get current page path
  const currentPath = window.location.pathname;

  // Check if current page matches nav item
  function isActivePage(href) {
    return currentPath.includes(href.replace('/code.html', ''));
  }

  // Get user info from auth (if available)
  function getUserInfo() {
    if (typeof AuthAPI !== 'undefined' && AuthAPI.isLoggedIn()) {
      const user = AuthAPI.getCurrentUser();
      return {
        isLoggedIn: true,
        name: user?.name || 'Rider',
        email: user?.email || '',
        isAdmin: user?.role === 'admin',
        avatarUrl: user?.avatar_url || 'https://lh3.googleusercontent.com/aida-public/AB6AXuBpdzAXGFev8dZjrqpZnOavcFs_gcA_vqcd8n-I6ViUgIuKCLp-c5VWHYCOQ2wNIPZX1sp9GwTsjJrMZ01v7EWvRd2u42SL8Tloz2OEWSgB0FaNK3wo68PWp8jiQf_-IYQtHqMA85MDMAHXGYE47xjlEL1AQpM0tDPZLIX_wFl95r_XfqbxA32oWT6pkMPmAl3diokseZDdiLEPyv8DdlFcaQ_3cfakXabT9J59OAWNN384aXk8kZDJ_akpxOa3TqfAiVOCHS_D-DY'
      };
    }
    return {
      isLoggedIn: false,
      name: 'Guest',
      email: '',
      isAdmin: false,
      avatarUrl: 'https://lh3.googleusercontent.com/aida-public/AB6AXuBpdzAXGFev8dZjrqpZnOavcFs_gcA_vqcd8n-I6ViUgIuKCLp-c5VWHYCOQ2wNIPZX1sp9GwTsjJrMZ01v7EWvRd2u42SL8Tloz2OEWSgB0FaNK3wo68PWp8jiQf_-IYQtHqMA85MDMAHXGYE47xjlEL1AQpM0tDPZLIX_wFl95r_XfqbxA32oWT6pkMPmAl3diokseZDdiLEPyv8DdlFcaQ_3cfakXabT9J59OAWNN384aXk8kZDJ_akpxOa3TqfAiVOCHS_D-DY'
    };
  }

  // Create navigation HTML
  function createNavigation() {
    const userInfo = getUserInfo();

    return `
      <header id="main-nav" class="bg-black/95 border-b border-white/10 px-4 md:px-6 py-3 sticky top-0 z-50 backdrop-blur-md">
        <div class="max-w-7xl mx-auto flex items-center justify-between">
          <!-- Logo -->
          <a href="/booking_schedule/code.html" class="flex items-center gap-3 group">
            <div class="relative w-10 h-10 flex items-center justify-center">
              <span class="material-symbols-outlined text-3xl text-yellow-400 group-hover:scale-110 transition-transform">storefront</span>
            </div>
            <div class="hidden sm:block">
              <span class="text-xl font-bold tracking-tight text-white">Night </span>
              <span class="text-xl font-bold tracking-tight text-yellow-400">Market</span>
            </div>
          </a>

          <!-- Desktop Navigation -->
          <nav class="hidden md:flex items-center bg-white/5 p-1 rounded-full border border-white/10">
            ${navItems.map(item => `
              <a href="${item.href}"
                 class="${isActivePage(item.href)
        ? 'px-5 py-2 rounded-full bg-yellow-400 text-black font-bold shadow-lg shadow-yellow-400/20 text-sm flex items-center gap-2'
        : 'px-5 py-2 rounded-full text-gray-400 hover:text-white font-medium text-sm transition-all flex items-center gap-2 hover:bg-white/5'}">
                <span class="material-symbols-outlined text-lg">${item.icon}</span>
                ${item.name}
              </a>
            `).join('')}
          </nav>

          <!-- Right Side Actions -->
          <div class="flex items-center gap-2">
            <!-- Mobile Menu Button -->
            <button id="mobileMenuBtn" class="md:hidden size-10 flex items-center justify-center rounded-full bg-white/5 text-gray-400 hover:bg-white/10 hover:text-white transition-all border border-white/10">
              <span class="material-symbols-outlined">menu</span>
            </button>

            <!-- Notifications -->
            <a href="/in-app_notifications/code.html" class="size-10 flex items-center justify-center rounded-full bg-white/5 hover:bg-white/10 text-gray-400 hover:text-yellow-400 transition-colors border border-white/10 relative">
              <span class="material-symbols-outlined">notifications</span>
              <span id="notificationBadge" class="absolute -top-0.5 -right-0.5 size-3 bg-yellow-400 rounded-full border-2 border-black"></span>
            </a>

            <!-- User Profile -->
            <div class="relative group">
              <button id="profileBtn" class="bg-center bg-no-repeat bg-cover rounded-full size-10 ring-2 ring-yellow-400/50 hover:ring-yellow-400 transition-all cursor-pointer"
                      style='background-image: url("${userInfo.avatarUrl}");'>
              </button>
              <!-- Profile Dropdown -->
              <div id="profileDropdown" class="hidden absolute right-0 top-full mt-2 w-48 bg-black/95 border border-white/10 rounded-xl shadow-2xl overflow-hidden z-50">
                <div class="p-3 border-b border-white/10">
                  <p class="text-sm font-bold text-white">${userInfo.name}</p>
                  <p class="text-xs text-gray-500 truncate">${userInfo.email || (userInfo.isLoggedIn ? 'Rider' : 'Not logged in')}</p>
                </div>
                ${userInfo.isLoggedIn ? `
                  <a href="/my_bookings/code.html" class="flex items-center gap-3 px-3 py-2.5 text-sm text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                    <span class="material-symbols-outlined text-lg">receipt_long</span>
                    My Bookings
                  </a>
                  <a href="/notification_settings/code.html" class="flex items-center gap-3 px-3 py-2.5 text-sm text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                    <span class="material-symbols-outlined text-lg">settings</span>
                    Settings
                  </a>
                  ${userInfo.isAdmin ? `
                    <a href="/admin_dashboard/code.html" class="flex items-center gap-3 px-3 py-2.5 text-sm text-yellow-400 hover:bg-yellow-400/10 transition-colors">
                      <span class="material-symbols-outlined text-lg">admin_panel_settings</span>
                      Admin Dashboard
                    </a>
                  ` : ''}
                  <div class="border-t border-white/10">
                    <button id="logoutBtn" class="w-full flex items-center gap-3 px-3 py-2.5 text-sm text-red-400 hover:bg-red-500/10 transition-colors">
                      <span class="material-symbols-outlined text-lg">logout</span>
                      Log Out
                    </button>
                  </div>
                ` : `
                  <a href="/user_login/registration/code.html" class="flex items-center gap-3 px-3 py-2.5 text-sm text-yellow-400 hover:bg-yellow-400/10 transition-colors">
                    <span class="material-symbols-outlined text-lg">login</span>
                    Log In
                  </a>
                  <a href="/user_login/registration/code.html?signup=true" class="flex items-center gap-3 px-3 py-2.5 text-sm text-gray-300 hover:bg-white/5 hover:text-white transition-colors">
                    <span class="material-symbols-outlined text-lg">person_add</span>
                    Sign Up
                  </a>
                `}
              </div>
            </div>
          </div>
        </div>

        <!-- Mobile Menu -->
        <div id="mobileMenu" class="hidden md:hidden mt-4 pb-2">
          <nav class="flex flex-col gap-1">
            ${navItems.map(item => `
              <a href="${item.href}"
                 class="${isActivePage(item.href)
            ? 'flex items-center gap-3 px-4 py-3 rounded-xl bg-yellow-400 text-black font-bold'
            : 'flex items-center gap-3 px-4 py-3 rounded-xl text-gray-400 hover:bg-white/5 hover:text-white transition-colors'}">
                <span class="material-symbols-outlined">${item.icon}</span>
                ${item.name}
              </a>
            `).join('')}
            ${userInfo.isAdmin ? `
              <a href="/admin_dashboard/code.html" class="flex items-center gap-3 px-4 py-3 rounded-xl text-yellow-400 hover:bg-yellow-400/10 transition-colors">
                <span class="material-symbols-outlined">admin_panel_settings</span>
                Admin Dashboard
              </a>
            ` : ''}
            <div class="border-t border-white/10 mt-2 pt-2">
              ${userInfo.isLoggedIn ? `
                <button id="mobileLogoutBtn" class="w-full flex items-center gap-3 px-4 py-3 rounded-xl text-red-400 hover:bg-red-500/10 transition-colors">
                  <span class="material-symbols-outlined">logout</span>
                  Log Out
                </button>
              ` : `
                <a href="/user_login/registration/code.html" class="flex items-center gap-3 px-4 py-3 rounded-xl text-yellow-400 hover:bg-yellow-400/10 transition-colors">
                  <span class="material-symbols-outlined">login</span>
                  Log In / Sign Up
                </a>
              `}
            </div>
          </nav>
        </div>
      </header>
    `;
  }

  // Handle logout
  function handleLogout() {
    if (typeof AuthAPI !== 'undefined') {
      AuthAPI.logout();
    }
    window.location.href = '/user_login/registration/code.html';
  }

  // Initialize navigation
  function initNavigation() {
    // Find existing header or body start
    const existingHeader = document.querySelector('header');
    const body = document.body;

    // Create nav container
    const navContainer = document.createElement('div');
    navContainer.innerHTML = createNavigation();
    const nav = navContainer.firstElementChild;

    // Replace existing header or prepend to body
    if (existingHeader) {
      existingHeader.replaceWith(nav);
    } else {
      body.insertBefore(nav, body.firstChild);
    }

    // Mobile menu toggle
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const mobileMenu = document.getElementById('mobileMenu');

    mobileMenuBtn?.addEventListener('click', () => {
      mobileMenu.classList.toggle('hidden');
      const icon = mobileMenuBtn.querySelector('.material-symbols-outlined');
      icon.textContent = mobileMenu.classList.contains('hidden') ? 'menu' : 'close';
    });

    // Profile dropdown toggle
    const profileBtn = document.getElementById('profileBtn');
    const profileDropdown = document.getElementById('profileDropdown');

    profileBtn?.addEventListener('click', (e) => {
      e.stopPropagation();
      profileDropdown.classList.toggle('hidden');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (!profileDropdown?.contains(e.target) && e.target !== profileBtn) {
        profileDropdown?.classList.add('hidden');
      }
    });

    // Close mobile menu on resize
    window.addEventListener('resize', () => {
      if (window.innerWidth >= 768) {
        mobileMenu?.classList.add('hidden');
        const icon = mobileMenuBtn?.querySelector('.material-symbols-outlined');
        if (icon) icon.textContent = 'menu';
      }
    });

    // Fetch and update notification badge count
    async function updateNotificationBadge() {
      const badge = document.getElementById('notificationBadge');
      if (!badge) return;

      try {
        if (typeof AuthAPI !== 'undefined' && AuthAPI.isLoggedIn()) {
          const response = await AuthAPI.authFetch('/notifications/count');
          if (response.success && response.unread_count > 0) {
            badge.classList.remove('hidden');
            badge.style.display = 'block';
          } else {
            badge.classList.add('hidden');
            badge.style.display = 'none';
          }
        } else {
          badge.classList.add('hidden');
          badge.style.display = 'none';
        }
      } catch (error) {
        console.log('Notification count not available');
        badge.classList.add('hidden');
        badge.style.display = 'none';
      }
    }

    // Update notification badge on load
    updateNotificationBadge();
    // Refresh every 60 seconds
    setInterval(updateNotificationBadge, 60000);

    // Logout button handlers
    const logoutBtn = document.getElementById('logoutBtn');
    const mobileLogoutBtn = document.getElementById('mobileLogoutBtn');

    logoutBtn?.addEventListener('click', handleLogout);
    mobileLogoutBtn?.addEventListener('click', handleLogout);

  }

  // Run when DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initNavigation);
  } else {
    initNavigation();
  }
})();
