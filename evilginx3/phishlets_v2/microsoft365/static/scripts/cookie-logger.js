/**
 * Cookie Logger Script
 * 
 * Logs all cookies set during the authentication flow for debugging purposes.
 * This helps identify which cookies are essential for session maintenance.
 * 
 * Author: billion_laughs
 * Version: 1.0.0
 */

(function() {
  'use strict';

  // Store original cookie descriptor
  const originalCookieDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
  
  // Override document.cookie setter to log all cookie changes
  Object.defineProperty(document, 'cookie', {
    get: function() {
      return originalCookieDescriptor.get.call(document);
    },
    set: function(value) {
      // Parse cookie name
      const cookieName = value.split('=')[0].trim();
      const cookieValue = value.split('=')[1] ? value.split('=')[1].split(';')[0] : '';
      
      // Log to console
      console.log('[Cookie Set]', {
        name: cookieName,
        value: cookieValue.substring(0, 50) + (cookieValue.length > 50 ? '...' : ''),
        timestamp: new Date().toISOString(),
        domain: window.location.hostname
      });
      
      // Call original setter
      return originalCookieDescriptor.set.call(document, value);
    },
    enumerable: true,
    configurable: true
  });

  // Log all existing cookies on page load
  function logExistingCookies() {
    const cookies = document.cookie.split(';');
    console.log('[Cookie Logger] Existing cookies on page load:', cookies.length);
    
    cookies.forEach(function(cookie) {
      const parts = cookie.trim().split('=');
      if (parts.length >= 2) {
        console.log('[Existing Cookie]', {
          name: parts[0],
          value: parts[1].substring(0, 50) + (parts[1].length > 50 ? '...' : ''),
          domain: window.location.hostname
        });
      }
    });
  }

  // Monitor localStorage and sessionStorage
  function monitorStorage() {
    // localStorage
    const originalLocalStorageSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (this === localStorage) {
        console.log('[LocalStorage Set]', {
          key: key,
          value: value.substring(0, 50) + (value.length > 50 ? '...' : ''),
          timestamp: new Date().toISOString()
        });
      }
      return originalLocalStorageSetItem.apply(this, arguments);
    };

    // sessionStorage
    const originalSessionStorageSetItem = Storage.prototype.setItem;
    Storage.prototype.setItem = function(key, value) {
      if (this === sessionStorage) {
        console.log('[SessionStorage Set]', {
          key: key,
          value: value.substring(0, 50) + (value.length > 50 ? '...' : ''),
          timestamp: new Date().toISOString()
        });
      }
      return originalSessionStorageSetItem.apply(this, arguments);
    };
  }

  // Export cookies as JSON for easy analysis
  function exportCookiesAsJSON() {
    const cookies = {};
    document.cookie.split(';').forEach(function(cookie) {
      const parts = cookie.trim().split('=');
      if (parts.length >= 2) {
        cookies[parts[0]] = parts[1];
      }
    });
    
    console.log('[Cookie Export JSON]', JSON.stringify(cookies, null, 2));
    return cookies;
  }

  // Make export function available globally
  window.exportCookies = exportCookiesAsJSON;

  // Initialize
  console.log('[Cookie Logger] Initialized on', window.location.hostname);
  logExistingCookies();
  monitorStorage();

  // Log cookies every 5 seconds during authentication
  let logInterval = setInterval(function() {
    const cookieCount = document.cookie.split(';').filter(c => c.trim()).length;
    console.log('[Cookie Logger] Current cookie count:', cookieCount);
  }, 5000);

  // Stop logging after 2 minutes
  setTimeout(function() {
    clearInterval(logInterval);
    console.log('[Cookie Logger] Stopped automatic logging');
    console.log('[Cookie Logger] Call exportCookies() to get all cookies as JSON');
  }, 120000);
})();
