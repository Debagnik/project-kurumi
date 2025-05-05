const rateLimit = require('express-rate-limit');

/**
 * Creates a standardized rate limiter middleware.
 * 
 * Applies common settings like enabling standard `RateLimit-*` headers
 * and disabling legacy headers, while allowing custom rate limit values.
 *
 * @param {Object} options - Rate limiter configuration.
 * @param {number} options.windowMs - Time window for rate limit in milliseconds.
 * @param {number} options.max - Maximum number of allowed requests per window.
 * @param {string} options.message - Message to send when limit is exceeded.
 * @returns {import('express-rate-limit').RateLimitRequestHandler} Express middleware for rate limiting.
 */
function createRateLimiter({ windowMs, max, message }) {
  return rateLimit({
    windowMs,
    max,
    message: { code: 429, message }, // Return JSON
    standardHeaders: true,
    legacyHeaders: false,
  });
}

/**
 * Rate limiter for AI-powered post summarization feature.
 *
 * Limits each IP to 10 requests per minute to prevent overuse of AI resources.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const aiSummaryRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 10,
  message: 'Too many summary generation attempts, please try again later.',
});

/**
 * Rate limiter for authentication endpoints (e.g., login forms).
 *
 * Limits each IP to 5 requests every 15 minutes to mitigate brute-force attacks.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const authRateLimiter = createRateLimiter({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: 'Too many login attempts in a short time, please try again later.',
});

/**
 * Rate limiter for generic admin routes (e.g., admin dashboard).
 *
 * Limits each IP to 50 requests per minute to ensure server stability.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const genericAdminRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 50,
  message: 'Ohh, Slow down choom, you are gonna kill us, again! - Jonny Silverhand',
});

/**
 * Rate limiter for generic open (public) routes.
 *
 * Limits each IP to 5 requests per minute to prevent abuse from unauthenticated traffic.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const genericOpenRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 50,
  message: `Your Kita-aura is too high, It's blinding the Bocchi. Slow down please`,
});

/**
 * Rate limiter for comments posting routes.
 *
 * Limits each IP to 20 requests per minute to prevent abuse from unauthenticated traffic.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const commentsRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 20,
  message: `You're shooting requests faster than I can dodge! Give me a break, okay? - Chisato`,
});

/**
 * Generic Rate limiter for get requests
 *
 * Limits each IP to 200 requests per minute to prevent abuse from unauthenticated traffic.
 *
 * @constant
 * @type {import('express-rate-limit').RateLimitRequestHandler}
 */
const genericGetRequestRateLimiter = createRateLimiter({
  windowMs: 60 * 1000, // 1 minute
  max: 200,
  message: `This pace... even Himmel the hero would have told you to breathe first. Slow Down - Frienen`,
});

module.exports = {
  aiSummaryRateLimiter,
  authRateLimiter,
  genericAdminRateLimiter,
  genericOpenRateLimiter,
  commentsRateLimiter,
  genericGetRequestRateLimiter
};
