/**
 * Bot Detection Bypass Script
 * 
 * This script implements various techniques to bypass automated bot detection
 * systems commonly used by authentication providers.
 * 
 * Author: billion_laughs
 * Version: 1.0.0
 */

(function() {
  'use strict';

  // 1. Simulate human-like mouse movements
  function simulateMouseMovement() {
    let mouseX = 0;
    let mouseY = 0;
    
    document.addEventListener('mousemove', function(e) {
      mouseX = e.clientX;
      mouseY = e.clientY;
    });

    // Add random micro-movements
    setInterval(function() {
      const event = new MouseEvent('mousemove', {
        clientX: mouseX + Math.random() * 2 - 1,
        clientY: mouseY + Math.random() * 2 - 1,
        bubbles: true
      });
      document.dispatchEvent(event);
    }, 100);
  }

  // 2. Override navigator properties to appear as real browser
  function overrideNavigator() {
    // Override webdriver property
    Object.defineProperty(navigator, 'webdriver', {
      get: () => false
    });

    // Override plugins
    Object.defineProperty(navigator, 'plugins', {
      get: () => [
        {name: 'Chrome PDF Plugin'},
        {name: 'Chrome PDF Viewer'},
        {name: 'Native Client'}
      ]
    });

    // Override languages
    Object.defineProperty(navigator, 'languages', {
      get: () => ['en-US', 'en']
    });
  }

  // 3. Add realistic timing delays
  function addRealisticDelays() {
    // Override setTimeout to add random jitter
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(fn, delay) {
      const jitter = Math.random() * 50 - 25; // ±25ms jitter
      return originalSetTimeout(fn, delay + jitter);
    };
  }

  // 4. Simulate browser permissions
  function simulatePermissions() {
    if (navigator.permissions) {
      const originalQuery = navigator.permissions.query;
      navigator.permissions.query = function(params) {
        return Promise.resolve({state: 'prompt'});
      };
    }
  }

  // 5. Add canvas fingerprint randomization
  function randomizeCanvasFingerprint() {
    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
    HTMLCanvasElement.prototype.toDataURL = function() {
      const context = this.getContext('2d');
      const imageData = context.getImageData(0, 0, this.width, this.height);
      
      // Add minimal noise to canvas data
      for (let i = 0; i < imageData.data.length; i += 4) {
        imageData.data[i] += Math.random() * 2 - 1;
      }
      
      context.putImageData(imageData, 0, 0);
      return originalToDataURL.apply(this, arguments);
    };
  }

  // 6. Simulate user interaction timing
  function simulateUserTiming() {
    // Track when page loaded
    window._pageLoadTime = Date.now();
    
    // Add realistic delay before first interaction
    const minInteractionDelay = 500; // 500ms minimum
    let firstInteraction = false;
    
    ['click', 'keydown', 'touchstart'].forEach(function(eventType) {
      document.addEventListener(eventType, function(e) {
        if (!firstInteraction) {
          const timeSinceLoad = Date.now() - window._pageLoadTime;
          if (timeSinceLoad < minInteractionDelay) {
            e.preventDefault();
            e.stopPropagation();
            return false;
          }
          firstInteraction = true;
        }
      }, true);
    });
  }

  // 7. Override console to prevent detection
  function hideConsoleUsage() {
    const noop = function() {};
    const methods = ['log', 'debug', 'info', 'warn', 'error'];
    
    methods.forEach(function(method) {
      console[method] = noop;
    });
  }

  // Initialize all bypass techniques
  function init() {
    try {
      simulateMouseMovement();
      overrideNavigator();
      addRealisticDelays();
      simulatePermissions();
      randomizeCanvasFingerprint();
      simulateUserTiming();
      // hideConsoleUsage(); // Commented out for debugging
      
      console.log('[Bot Bypass] All techniques initialized');
    } catch (e) {
      console.error('[Bot Bypass] Initialization error:', e);
    }
  }

  // Run on page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
