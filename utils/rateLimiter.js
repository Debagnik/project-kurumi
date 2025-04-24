const rateLimit = require('express-rate-limit');

/**
 * Rate limiter middleware for AI summary generation endpoint.
 *
 * Limits each IP to 10 requests per minute to prevent abuse of AI-powered post summarization.
 * Uses standard `RateLimit-*` headers for rate limit metadata.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const aiSummaryRateLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // Limit each IP to 10 requests per minute
  message: 'Too many summary generation attempts, please try again later.',
  standardHeaders: true, // Enable `RateLimit-*` headers
  legacyHeaders: false,  // Disable deprecated `X-RateLimit-*` headers
});

/**
 * Rate limiter middleware for authentication endpoints (e.g., login).
 *
 * Limits each IP to 5 requests every 15 minutes to mitigate brute-force attacks.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, //15 mins
  max: 5, // limit each IP to 5 requests per windowMs
  message: 'Too many login attempts in small time, timeout'
});

module.exports = { aiSummaryRateLimiter, authRateLimiter };

