const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const post = require('../models/posts');
const user = require('../models/user');
const comment = require('../models/comments');
const csrf = require('csurf');
const verifyCloudflareTurnstileToken = require('../../utils/cloudflareTurnstileServerVerify.js');
const sanitizeHtml = require('sanitize-html');
const mongoose = require('mongoose');
const utils = require('../../utils/validations.js');
const { fetchSiteConfigCached, getCacheStatus } = require('../../utils/fetchSiteConfigurations.js');
const { genericOpenRateLimiter, genericAdminRateLimiter, commentsRateLimiter, genericGetRequestRateLimiter } = require('../../utils/rateLimiter');
const { CONSTANTS } = require('../../utils/constants.js');
const postCache = require('../../utils/postCache.js');

const jwtSecretKey = process.env.JWT_SECRET;


//Use Middleware.
router.use(fetchSiteConfigCached);

/**
 * @config JWT Secret Validation
 * @description Ensures that the application has a valid JWT secret key defined
 *              in the environment variables before starting. Prevents insecure
 *              operation without proper signing credentials.
 * 
 * @check
 * @condition Exits the process if `process.env.JWT_SECRET` is undefined or empty
 * @log Logs a descriptive error message before terminating
 * 
 * @security
 * @requires JWT secret to be present for token signing/verification
 * @failsafe Prevents server startup without required secret
 * 
 * @exit
 * @code 1 - Graceful shutdown when secret is missing
 * 
 * ---
 * 
 * @middleware CSRF Protection
 * @description Applies CSRF protection middleware globally to all routes
 *              under this router, using cookie-based token storage.
 * 
 * @implementation
 * @uses csurf - CSRF protection middleware
 * @option {boolean} cookie=true - Stores CSRF tokens in cookies
 * 
 * @security
 * @protects Against Cross-Site Request Forgery attacks on state-changing routes
 * @enforces Valid CSRF token on POST, PUT, DELETE, etc.
 * 
 * @scope Router-wide
 * @applied router.use(csrfProtection)
 */
if (!jwtSecretKey) {
    console.error('JWT_SECRET is not defined. Please set it in your environment variables.');
    // You might want to exit the process gracefully
    process.exit(1);
}

// adding admin CSRF protection middleware
const csrfProtection = csrf({ cookie: true });
router.use(csrfProtection);

//Routes


/**
 * @route GET /api/test/getCsrfToken
 * @description Provides a CSRF token for testing or development purposes.
 *              Token is only returned when the app is running in a development
 *              environment (`development` or `dev-local`).
 * 
 * @middleware
 * @chain csrfProtection - Enforces CSRF middleware to generate and validate tokens
 * @chain genericGetRequestRateLimiter - Protects endpoint from excessive requests
 * 
 * @environment
 * @allow Development only:
 *         - NODE_ENV=development
 *         - NODE_ENV=dev-local
 * @deny All other environments (returns Forbidden)
 * 
 * @response
 * @success {200} JSON payload containing:
 *           @property {string} csrfToken - The generated CSRF token
 * @failure {403} JSON response with:
 *           @property {string} message - "Forbidden"
 * 
 * @security
 * @protects Ensures CSRF tokens are not exposed in production
 * @rateLimited Prevents abuse of token-fetching in development
 * 
 * @access Restricted (development/local only)
 * 
 * @errorHandling
 * @forbidden Explicit rejection outside of allowed environments
 * 
 * @useCase
 * @example Development clients can call this endpoint to fetch a CSRF token
 *          for testing POST/PUT/DELETE requests in local environments.
 */
router.get('/api/test/getCsrfToken', csrfProtection, genericGetRequestRateLimiter, (req, res) => {
    if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'dev-local') {
        return res.status(200).json({ csrfToken: req.csrfToken() });
    }
    else {
        return res.status(403).json({ message: 'Forbidden' });
    }
});

/**
 * @route GET /
 * @description Renders the home page of the application, displaying a paginated
 *              list of approved blog posts in descending order of creation date.
 * 
 * @middleware
 * @chain genericOpenRateLimiter - Applies rate limiting to protect the public-facing home page
 * 
 * @locals
 * @param {string} title - The site name from `res.locals.siteConfig` (default: "Project Walnut")
 * @param {string} description - The site metadata description from config
 * @param {Object} config - Complete site configuration object available in locals
 * 
 * @pagination
 * @param {number} perPage - Number of posts per page (from site config, default: 1)
 * @param {number} page - Current page number (from query param `?page=`, default: 1)
 * @computed
 *   - nextPage {number|null} - Next page number, if available
 *   - previousPage {number|null} - Previous page number, if available
 *   - totalPages {number} - Total number of pages based on approved post count
 * 
 * @database
 * @collection posts
 * @query
 *   - Filters only `{ isApproved: true }`
 *   - Sorts results by `createdAt: -1` (most recent first)
 *   - Applies pagination via `.skip()` and `.limit()`
 * 
 * @response
 * @success {200} Renders the `index` view with:
 *   - locals (title, description, config)
 *   - data (paginated posts)
 *   - currentPage, nextPage, previousPage
 *   - csrfToken for form submissions
 *   - totalPages for navigation
 * @failure {500} Logs error to console if DB query/render fails
 * 
 * @security
 * @rateLimited Prevents excessive requests to the home page
 * @csrfToken Included in rendered template to protect POST requests from CSRF
 * 
 * @logging
 * Logs "DB Posts Data fetched" to console when posts are successfully retrieved.
 * Logs error details to console on query/render failure.
 * 
 * @useCase
 * Visitors accessing the root URL `/` can browse through approved blog posts
 * with pagination support, starting from the most recent content.
 */
router.get('', genericOpenRateLimiter, async (req, res) => {

    try {
        const locals = {
            title: res.locals.siteConfig.siteName || "Project Walnut",
            description: res.locals.siteConfig.siteMetaDataDescription || "A blogging site created with Node, express and MongoDB",
            config: res.locals.siteConfig,
        }

        let perPage = res.locals.siteConfig.defaultPaginationLimit || 1;
        let page = parseInt(req.query.page) || 1;

        const data = await post.aggregate([
            { $match: { isApproved: true } },
            { $sort: { createdAt: -1 } }
        ]).skip(perPage * page - perPage).limit(perPage).exec();

        const count = await post.countDocuments({ isApproved: true });
        const nextPage = parseInt(page) + 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);

        const previousPage = parseInt(page) - 1;
        const hasPreviousPage = previousPage >= 1;


        res.render('index', {
            locals,
            data,
            currentPage: page,
            nextPage: hasNextPage ? nextPage : null,
            previousPage: hasPreviousPage ? previousPage : null,
            csrfToken: req.csrfToken(),
            totalPages: Math.ceil(count / perPage)
        });
        console.log(`DB Posts Data fetched`);
    } catch (error) {
        console.log(error);
    }
});

/**
 * @route GET /about
 * @description Renders the "About Us" page with site configuration and metadata.
 *              Provides page title, description, CSRF token, and config to the template.
 * 
 * @locals
 * @param {string} title - "About Us Section - <siteName>" (defaults to "Project Walnut" if missing)
 * @param {string} description - Static description: "A blogging site created with Node, express and MongoDB"
 * @param {Object} config - Site-wide configuration from `res.locals.siteConfig`
 * @chain genericOpenRateLimiter - Protects route from abuse with rate limiting
 * 
 * @response
 * @success {200} Renders the `about` EJS template with:
 *   - locals (title, description, config)
 *   - csrfToken for secure form submissions
 * 
 * @security
 * @csrfToken Included in rendered template to protect any interactive form on the page
 * @rateLimited Prevents excessive requests to the about page
 * 
 * @access Public (no authentication required)
 * 
 * @logging
 * None explicitly (no DB calls or console logs here)
 * 
 * @useCase
 * Provides visitors with an informational "About Us" section, highlighting
 * the purpose of the site and its underlying stack.
 */
router.get('/about', genericOpenRateLimiter, (req, res) => {
    const locals = {
        title: 'About Us Section' + ' - ' + (res.locals.siteConfig.siteName || 'Project Walnut'),
        description: "A blogging site created with Node, express and MongoDB",
        config: res.locals.siteConfig
    }
    res.render('about', {
        locals,
        csrfToken: req.csrfToken()
    });
});

/**
 * @route GET /contact
 * @description Renders the "Contact Us" page with site configuration and metadata.
 *              Supplies the template with page title, description, configuration, and CSRF protection.
 * 
 * @locals
 * @param {string} title - "Contacts us - <siteName>" (defaults to "Project Walnut" if missing)
 * @param {string} description - Static description: "A blogging site created with Node, express and MongoDB"
 * @param {Object} config - Site-wide configuration from `res.locals.siteConfig`
 * @chain genericOpenRateLimiter - Protects route from abuse with rate limiting
 * 
 * @response
 * @success {200} Renders the `contact` EJS template with:
 *   - locals (title, description, config)
 *   - csrfToken for secure form submissions
 * 
 * @security
 * @csrfToken Included in rendered template to protect any form on the page
 * @rateLimited Prevents excessive requests to the contact page
 * 
 * @access Public (no authentication required)
 * 
 * @logging
 * None explicitly (no DB calls or console logs here)
 * 
 * @useCase
 * Provides a contact form/page to allow visitors to reach out to the site owners/admins.
 */
router.get('/contact', genericOpenRateLimiter, (req, res) => {
    const locals = {
        title: "Contacts us" + ' - ' + (res.locals.siteConfig.siteName || 'Project Walnut'),
        description: "A blogging site created with Node, express and MongoDB",
        config: res.locals.siteConfig
    }
    res.render('contact', {
        locals,
        csrfToken: req.csrfToken()
    });
});

/**
 * @route GET /post/:id
 * @description Fetches and renders a single blog post by its MongoDB `_id`. 
 *              Enriches the post with author details, site config, captcha settings, 
 *              and associated comments before rendering.
 * @deprecated Since 3.0.0 - Use `/posts/:uniqueId` instead
 * @middleware
 * @chain genericOpenRateLimiter - Protects route from abuse with rate limiting
 * 
 * @params
 * @param {string} id - MongoDB `_id` of the post to retrieve
 * 
 * @process
 * @step Extracts post ID from `req.params.id`
 * @step Fetches post data by `_id` from the database
 * @step Retrieves author details; defaults to "Anonymous" if missing
 * @step Constructs locals for title, description, keywords, and site config
 * @step Checks if captcha is enabled in `siteConfig`
 * @step Determines if the current user is Admin/Moderator
 * @step Fetches comments for the given post ID
 * 
 * @conditions
 * @check Post existence - throws error if not found
 * @check Post visibility - allowed if `data.isApproved` or current user is logged in
 * @check Redirects - non-approved post without logged-in user redirects to `/404`
 * 
 * @visibilityRules
 * @rule Approved posts → Publicly visible
 * @rule Unapproved posts → Only visible if:
 *       - Current user is logged in
 *       - OR Current user has elevated privileges (Admin/Moderator)
 * 
 * @response
 * @success {200} Renders the `posts` EJS template with:
 *   - locals (title, description, keywords, config)
 *   - data (post content + authorName)
 *   - csrfToken for secure interactions
 *   - isCaptchaEnabled flag
 *   - commentsData (fetched from `getCommentsFromPostId`)
 *   - currentUser (boolean for moderator/admin)
 * @failure {404} Redirects to `/404` on:
 *   - Missing post
 *   - Fetch errors
 * 
 * @security
 * @csrfToken Injected into template for form security
 * @rateLimited Prevents abuse via `genericOpenRateLimiter`
 * 
 * @logging
 * @errorLogs Logs post fetch errors and missing posts
 * 
 * @access Public (restricted for unapproved posts)
 */
router.get('/post/:id', genericOpenRateLimiter, async (req, res) => {
    try {
        console.warn('[DEPRECATED] The route /post/:id is deprecated since version 3.0.0. Please use /post/:uniqueId instead. Sunset date: TBD');
        const currentUser = await getUserFromCookieToken(req);

        let slug = req.params.id;
        const data = await post.findById({ _id: slug });
        if (!data) {
            throw new Error('404 - No such post found');
        }
        const locals = {
            title: data.title,
            description: data.desc,
            keywords: data.tags,
            config: res.locals.siteConfig
        }
        const postAuthor = await user.findOne({ username: data.author });
        if (!postAuthor) {
            data.authorName = 'Anonymous'
        } else {
            data.authorName = postAuthor.name;
        }

        const isCaptchaEnabled = res.locals.siteConfig.isCaptchaEnabled && !!res.locals.siteConfig.cloudflareSiteKey && !!res.locals.siteConfig.cloudflareServerKey;
        const isCurrentUserAModOrAdmin = currentUser && (currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.WEBMASTER || currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.MODERATOR);
        if (currentUser || data.isApproved) {
            res.set('Deprecation', 'true');
            res.set('Link', '/posts/:uniqueId; rel="successor-version"');
            res.render('posts', {
                locals,
                data,
                csrfToken: req.csrfToken(),
                isCaptchaEnabled,
                commentsData: await getCommentsFromPostId(data._id),
                currentUser: isCurrentUserAModOrAdmin
            });
        } else {
            res.set('Deprecation', 'true');
            res.set('Link', '/posts/:uniqueId; rel="successor-version"');
            res.redirect('/404');
        }

    } catch (error) {
        console.error('Post Fetch error', error);
        res.set('Deprecation', 'true');
        res.set('Link', '/posts/:uniqueId; rel="successor-version"');
        res.status(404).redirect('/404');
    }
});

/**
 * @route GET /posts/:uniqueId
 * @description Retrieves and renders a single blog post identified by its `uniqueId`.  
 *              Integrates author information, site configuration, captcha status, and 
 *              associated comments before rendering the view.  
 *              This route supersedes the deprecated `/post/:id` endpoint.
 *
 * @middleware
 * @chain genericOpenRateLimiter - Applies open rate-limiting to prevent abuse.
 *
 * @params
 * @param {string} uniqueId - The unique identifier of the post to retrieve.
 *
 * @process
 * @step 1. Extracts and sanitizes `uniqueId` from the request parameters.
 * @step 2. Attempts to fetch post data from the in-memory cache (`postCache`).
 * @step 3. On cache miss, retrieves post data from the database.
 * @step 4. Resolves the author name; defaults to `"Anonymous"` if unavailable.
 * @step 5. Stores the fetched and processed post back in the cache for reuse.
 * @step 6. Builds `locals` for rendering (title, description, keywords, and config).
 * @step 7. Evaluates captcha enablement and user privileges (Moderator/Admin).
 * @step 8. Retrieves associated comments via `getCommentsFromPostId`.
 *
 * @conditions
 * @check Post existence — Throws `404` if no matching post is found.
 * @check Post visibility — Allowed if the post is approved or the user is logged in.
 * @check Redirects — Unauthorized users requesting unapproved posts are redirected to `/404`.
 *
 * @visibilityRules
 * @rule Approved posts → Publicly accessible.
 * @rule Unapproved posts → Accessible only if:
 *       - The current user is authenticated, or
 *       - The current user has elevated privileges (Moderator/Admin).
 *
 * @response
 * @success {200} Renders the `posts` EJS template with:
 *   - `locals` → Metadata and configuration for rendering.
 *   - `data` → Post content including `authorName`.
 *   - `csrfToken` → Secure form token for submission.
 *   - `isCaptchaEnabled` → Boolean indicating if captcha is active.
 *   - `commentsData` → List of associated comments.
 *   - `currentUser` → Boolean flag for Moderator/Admin status.
 *
 * @failure {404} Redirects to `/404` when:
 *   - The post is missing.
 *   - An error occurs during fetch or rendering.
 *   - Access to an unapproved post is unauthorized.
 *
 * @security
 * @csrfToken Embedded into the rendered page for form validation.
 * @rateLimited Controlled via `genericOpenRateLimiter` to prevent request abuse.
 *
 * @logging
 * @infoLogs Logs cache hits and misses for post lookups.
 * @warnLogs Logs unauthorized attempts to view unapproved posts.
 * @errorLogs Logs database fetch errors and rendering issues.
 *
 * @access
 * Public (restricted for unapproved or unauthorized posts).
 */
router.get('/posts/:uniqueId', genericOpenRateLimiter, async (req, res) => {
    try {
        if (process.env.NODE_ENV !== 'production') {
            console.log(`Fetching post by uniqueId: ${req.params.uniqueId}`);
        }
        const currentUser = await getUserFromCookieToken(req);
        let cleanedUniqueId = sanitizeHtml(req.params.uniqueId, CONSTANTS.SANITIZE_FILTER);

        //check if post exist on postCache
        let data = null;
        data = postCache.getPostFromCache(cleanedUniqueId);
        if (!data) {
            if (process.env.NODE_ENV !== 'production') {
                console.log(`Post with UniqueId: ${cleanedUniqueId} not found on cache, trying to fetch from DB`);
            }
            data = await post.findOne({ uniqueId: cleanedUniqueId });
            if (!data) {
                throw new Error('404 - No such post found');
            }

            const postAuthor = await user.findOne({ username: data.author });
            if (!postAuthor || !postAuthor.name) {
                data.authorName = 'Anonymous';
            } else {
                data.authorName = postAuthor.name;
            }

            postCache.setPostToCache(cleanedUniqueId, data);

        } else {
            console.log(`Post with UniqueId: ${cleanedUniqueId} found on cache, skipping DB fetch`);
        }

        const locals = {
            title: data.title,
            description: data.desc,
            keywords: data.tags,
            config: res.locals.siteConfig
        };

        const isCaptchaEnabled = res.locals.siteConfig.isCaptchaEnabled && !!res.locals.siteConfig.cloudflareSiteKey && !!res.locals.siteConfig.cloudflareServerKey;
        const isCurrentUserAModOrAdmin = currentUser && (currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.WEBMASTER || currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.MODERATOR);

        if (currentUser || data.isApproved) {
            return res.render('posts', {
                locals,
                data,
                csrfToken: req.csrfToken(),
                isCaptchaEnabled,
                commentsData: await getCommentsFromPostId(data._id),
                currentUser: isCurrentUserAModOrAdmin
            });
        } else {
            if (process.env.NODE_ENV !== 'production') {
                console.warn(`Unlogged user tried fetching unapproved post`);
            }
            return res.status(404).redirect('/404');
        }
    } catch (error) {
        console.error('Post Fetch error', error);
        return res.status(404).redirect('/404');
    }

});

/**
 * @function getUserFromCookieToken
 * @description Retrieves the currently logged-in user from the request's cookies 
 *              by decoding and validating the JWT token stored in `req.cookies.token`.
 * 
 * @async
 * 
 * @params
 * @param {Object} req - Express request object
 * @param {Object} req.cookies - Cookie object containing `token`
 * 
 * @process
 * @step Extracts JWT token from `req.cookies.token`
 * @step Attempts to verify token using `jwtSecretKey`
 * @step Extracts `userId` from decoded token payload if valid
 * @step Queries database for user record via `user.findById(userId)`
 * 
 * @conditions
 * @check If token is missing → Skips lookup and returns `null`
 * @check If token is invalid/expired → Logs error and returns `null`
 * @check If user not found → Returns `null`
 * 
 * @response
 * @returns {Object|null} Current user document from database, or `null` if:
 *   - No token present
 *   - Token invalid/expired
 *   - User does not exist
 * 
 * @security
 * @jwtValidation Ensures token authenticity using `jwtSecretKey`
 * @errorHandling Logs invalid token attempts without crashing server
 * 
 * @logging
 * @errorLogs Invalid or expired token verification failures
 * 
 * @access Private (utility function, not an exposed route)
 */
const getUserFromCookieToken = async (req) => {
    let currentUser = null;
    const token = req.cookies.token;
    let userId = null;
    if (token) {
        try {
            const decoded = jwt.verify(token, jwtSecretKey);
            userId = decoded.userId;
        } catch (err) {
            console.error('Invalid token:', err.message);
        }
    }
    if (userId) {
        currentUser = await user.findById(userId);
    }
    return currentUser;
}

/**
 * @function getCommentsFromPostId
 * @description Fetches comments associated with a specific post ID from the database.
 *              Limits the number of returned comments according to environment settings
 *              and applies descending timestamp sorting.
 * 
 * @async
 * 
 * @params
 * @param {string} postId - MongoDB `_id` of the post for which to fetch comments
 * 
 * @process
 * @step Reads `MAX_COMMENTS_LIMIT` from environment variables
 * @step Clamps the limit between `CONSTANTS.CLAMP_COMMENT_MIN` and `CONSTANTS.CLAMP_COMMENT_MAX`
 * @step Uses default `CONSTANTS.DEFAULT_COMMENT_LIMIT` if `MAX_COMMENTS_LIMIT` is missing or invalid
 * @step Queries `comment` collection for `postId`
 * @step Sorts results by `commentTimestamp` in descending order
 * @step Applies the computed `limit` to the query
 * 
 * @response
 * @returns {Array} List of comment documents for the specified post.
 *                  Returns an empty array if no comments are found or if an error occurs.
 * 
 * @conditions
 * @check Invalid or missing `MAX_COMMENTS_LIMIT` → Uses default comment limit
 * @check Database query failure → Logs error and returns empty array
 * 
 * @security
 * @readOnly Fetch operation only, no modifications
 * 
 * @logging
 * @errorLogs Includes post ID and error message on DB fetch failure
 * 
 * @access Private (utility function, intended for internal route helpers)
 */
const getCommentsFromPostId = async (postId) => {
    try {
        const rawLimit = parseInt(process.env.MAX_COMMENTS_LIMIT, 10);
        const limit = Number.isFinite(rawLimit) ? Math.max(CONSTANTS.CLAMP_COMMENT_MIN, Math.min(rawLimit, CONSTANTS.CLAMP_COMMENT_MAX)) : CONSTANTS.DEFAULT_COMMENT_LIMIT;

        const comments = await comment.find({ postId }).sort({ commentTimestamp: -1 }).limit(limit);
        return comments;
    } catch (error) {
        console.error('Comment Fetch error', postId, error.message);
        return [];
    }
}

/**
 * @route POST /search
 * @description Handles blog post searches, supporting both simple and advanced search modes.
 *              Allows searching by keyword, title, author, and tags. In advanced mode, falls back
 *              to regex search if no results are found. Paginates results and sanitizes all input.
 * 
 * @middleware
 * @chain genericOpenRateLimiter - Prevents abuse by limiting excessive search requests
 * 
 * @params
 * @param {string} searchTerm - Keyword to search across title/body
 * @param {string} title - Optional title filter
 * @param {string} author - Optional author name filter
 * @param {string} tags - Optional comma-separated tags filter
 * @param {boolean|string} isAdvancedSearch - Indicates advanced search mode (`true` or `false`)
 * @param {boolean|string} isNextPage - Used for pagination ('yes' = next, 'no' = previous)
 * @param {number|string} page - Page number for pagination
 * 
 * @process
 * @step Sanitizes all input using `sanitizeHtml`
 * @step Computes pagination limits and skip values
 * @step Constructs MongoDB filter conditions depending on search mode
 * @step Advanced search:
 *        - Keyword regex search in title/body
 *        - Title-specific regex search
 *        - Tag inclusion
 *        - Author name resolution to username
 *        - Fallback regex search if no results found
 * @step Simple search:
 *        - Performs text search on title/body using `$text`
 *        - Rejects invalid or empty keywords
 * @step Queries database for posts and counts total matching documents
 * @step Computes totalPages, nextPage, previousPage flags
 * @step Renders `search` EJS template with data, locals, pagination, and CSRF token
 * 
 * @conditions
 * @check Valid search mode (`isAdvancedSearch` must be boolean or string)
 * @check Keyword length must be within 1–100 characters for simple search
 * @check Pagination values corrected to valid integers
 * 
 * @response
 * @success {200} Renders `search` template with:
 *   - data: list of posts matching filters
 *   - locals: title, description, config
 *   - searchTerm, title, author, tags
 *   - pagination info: currentPage, nextPage, previousPage, totalPages
 *   - csrfToken for secure forms
 *   - isAdvancedSearch flag
 * @failure {400} Returns JSON errors for invalid keyword or search mode
 * @failure {500} Renders error page with site config and error message
 * 
 * @security
 * @csrfToken Included for protection in any form interactions
 * @rateLimited Prevents abusive search traffic
 * @sanitize All user inputs are sanitized to prevent XSS
 * 
 * @logging
 * @errorLogs Logs search execution errors along with stack traces
 * 
 * @access Public (anyone can search posts)
 * 
 * @pagination
 * @pageSize Controlled by `res.locals.siteConfig.searchLimit`
 * @pageValidation Ensures page number is >= 1
 * @nextPreviousFlags Calculated for UI navigation
 * 
 * @visibilityRules
 * @rule Only approved posts (`isApproved: true`) are returned to public users
 */
router.post('/search', genericOpenRateLimiter, async (req, res) => {
    try {
        const {
            searchTerm = '',
            title = '',
            author = '',
            tags = '',
            isAdvancedSearch,
            isNextPage,
        } = req.body;

        const searchLimit = res.locals.siteConfig.searchLimit;
        const rawPage = parseInt(req.body.page, 10);
        const currentPage = isNaN(rawPage) || rawPage < 1 ? 1 : rawPage;
        const page = isNextPage !== undefined
            ? (isNextPage === 'yes' ? currentPage + 1 : currentPage - 1)
            : currentPage;

        const skip = Math.max((page - 1) * searchLimit, 0);

        const locals = {
            title: 'Search - ' + (searchTerm || title || author || tags),
            description: 'Search Results',
            config: res.locals.siteConfig
        };

        const keyword = sanitizeHtml(searchTerm.trim(), { allowedTags: [], allowedAttributes: [] });
        const sanitizedTitle = sanitizeHtml(title.trim(), { allowedTags: [], allowedAttributes: [] });
        const sanitizedAuthor = sanitizeHtml(author.trim(), { allowedTags: [], allowedAttributes: [] });
        const tagArray = utils.parseTags(tags);

        let filter = { $and: [{ isApproved: true }] };
        let data = [];
        let count = 0;

        // === Advanced Search Logic ===
        if (isAdvancedSearch === 'true' || isAdvancedSearch === true) {
            const orConditions = [];

            // Keyword search (title/body)
            if (keyword) {
                const regex = new RegExp(keyword.replace(/[^a-zA-Z0-9 ]/g, ''), 'i');
                orConditions.push({ title: regex }, { body: regex });
            }

            // Title-specific search
            if (sanitizedTitle) {
                orConditions.push({ title: new RegExp(sanitizedTitle, 'i') });
            }

            // Tag search
            if (tagArray.length > 0) {
                filter.$and.push({ tags: { $in: tagArray } });
            }

            // Author name -> username resolution
            if (sanitizedAuthor) {
                const userModel = await user.findOne({
                    name: new RegExp('^' + sanitizedAuthor + '$', 'i')
                });

                if (userModel) {
                    filter.$and.push({ author: userModel.username });
                }
            }

            if (orConditions.length > 0) {
                filter.$and.push({ $or: orConditions });
            }

            // Initial query
            data = await post.find(filter).sort({ createdAt: -1 }).skip(skip).limit(searchLimit).exec();
            count = await post.countDocuments(filter);

            // Fallback: regex-only search if no results
            if (data.length === 0 && keyword) {
                const fallbackRegex = new RegExp(keyword, 'i');
                filter.$and = filter.$and.filter(condition => !condition.$text); // remove any accidental $text usage
                filter.$and.push({ $or: [{ title: fallbackRegex }, { body: fallbackRegex }] });

                data = await post.find(filter).sort({ createdAt: -1 }).skip(skip).limit(searchLimit).exec();
                count = await post.countDocuments(filter);
            }

        }
        // === Simple Search Logic ===
        else if (isAdvancedSearch === 'false' || isAdvancedSearch === false) {
            if (!keyword || keyword.length === 0 || keyword.length > 100) {
                return res.status(400).json({ error: 'Invalid keyword for simple search' });
            }

            filter.$and.push({ $text: { $search: keyword.replace(/[^a-zA-Z0-9 ]/g, '') } });

            data = await post.find(filter, { score: { $meta: 'textScore' } })
                .sort({ score: { $meta: 'textScore' } })
                .skip(skip)
                .limit(searchLimit)
                .exec();

            count = await post.countDocuments(filter);
        }
        // === Invalid Search Mode ===
        else {
            return res.status(400).json({ error: 'Missing or invalid isAdvancedSearch flag' });
        }

        const totalPages = Math.ceil(count / searchLimit);
        const nextPage = page + 1;
        const hasNextPage = nextPage <= totalPages;
        const previousPage = page - 1;
        const hasPreviousPage = previousPage >= 1;

        return res.render('search', {
            data,
            locals,
            searchTerm: keyword,
            title: sanitizedTitle,
            author: sanitizedAuthor,
            tags: req.body.tags,
            currentPage: page,
            nextPage: hasNextPage ? nextPage : null,
            previousPage: hasPreviousPage ? previousPage : null,
            totalPages,
            csrfToken: req.csrfToken(),
            isAdvancedSearch
        });

    } catch (error) {
        console.error('Search error:', error);
        return res.status(500).render('error', {
            locals: {
                title: 'Error',
                config: res.locals.siteConfig
            },
            error: 'Unable to perform search at this time'
        });
    }
});

/**
 * @route POST /post/:id/post-comments
 * @description Adds a new comment to a specific blog post. 
 *              Performs full validation, CAPTCHA verification (if enabled), and post existence/approval checks.
 *              Sanitizes all inputs to prevent XSS. Supports flash messages and redirects for user feedback.
 * 
 * @middleware
 * @chain commentsRateLimiter - Protects against comment spam and abuse
 * 
 * @params
 * @param {string} id - MongoDB `_id` of the post (route parameter)
 * @param {string} postId - Post ID submitted in request body (must match route parameter)
 * @param {string} commenterName - Name of the user submitting the comment
 * @param {string} commentBody - The actual comment text
 * @param {string} cf-turnstile-response - Optional Cloudflare CAPTCHA token for verification
 * 
 * @validation
 * @check postId must be a valid MongoDB ObjectId
 * @check commenterName must be between 3 and 50 characters
 * @check commentBody must be between 1 and 500 characters
 * @check post must exist and be approved
 * @check CAPTCHA token valid if siteConfig.isCaptchaEnabled
 * @sanitize All input fields using `sanitizeHtml`
 * 
 * @process
 * @step Verifies route and body post IDs match
 * @step Checks site config for comments enabled
 * @step Performs CAPTCHA verification via `verifyCloudflareTurnstileToken` if enabled
 * @step Sanitizes commenterName and commentBody
 * @step Creates and saves a new comment document in MongoDB
 * @step Logs success or failure based on environment (production/development)
 * @step Sends flash messages and redirects user back to the post page
 * 
 * @response
 * @success {200} Redirects back to `/post/:id` with success flash message
 * @failure {400} Redirects with flash if input validation fails (comment length or name issues)
 * @failure {403} Redirects if comments are disabled, CAPTCHA fails, or post is unapproved
 * @failure {404} Redirects to `/404` if post ID is invalid or post does not exist
 * @failure {500} Redirects with flash message if saving comment fails (internal server error)
 * 
 * @security
 * @csrfToken Used via site forms for CSRF protection
 * @rateLimited Prevents excessive comment submissions
 * @sanitize All user-provided input is sanitized to mitigate XSS
 * @captcha Optional human verification via Cloudflare Turnstile
 * 
 * @logging
 * @logs Comment submission attempts, errors, and environment-specific details
 * @logs both success and failure events
 * 
 * @access Public (anyone can comment if comments are enabled)
 */
router.post('/posts/:id/post-comments', commentsRateLimiter, async (req, res) => {
    const { postId, commenterName, commentBody } = req.body;
    const paramId = req.params.id;
    if (!mongoose.Types.ObjectId.isValid(paramId) || postId !== paramId) {
        req.flash('error', 'Invalid post reference');
        return res.status(404).redirect('/404');
    }
    if (!mongoose.Types.ObjectId.isValid(postId)) {
        req.flash('error', 'Invalid post reference');
        return res.status(404).redirect('/404');
    }
    let existingPost = null;
    try {
        existingPost = await post.findById(paramId);
    }
    catch (error) {
        console.error('Error fetching post for comment addition:', error);
    }
    if (!existingPost) {
        req.flash('error', 'No post found to comment on');
        return res.status(404).redirect('/404');
    }
    const siteConfig = res.locals.siteConfig;
    if (!siteConfig.isCommentsEnabled) {
        console.error({ "error": "403", "message": "Comments are disabled or Cloudflare keys are not set" });
        req.flash('error', 'Comments are disabled or Cloudflare keys are not set');
        return res.status(403).redirect(`/posts/${existingPost.uniqueId}`);
    }

    if (siteConfig.isCaptchaEnabled && (!siteConfig.cloudflareSiteKey || !siteConfig.cloudflareServerKey)) {
        console.error(403, 'CAPTCHA is enabled but Cloudflare keys are not set');
        req.flash('error', 'CAPTCHA config error, contact the webmaster.');
        return res.status(403).redirect(`/posts/${existingPost.uniqueId}`);
    }

    const captchaToken = req.body['cf-turnstile-response'];
    const remoteIp = req.ip;
    const secretKey = siteConfig.cloudflareServerKey;
    if (siteConfig.isCaptchaEnabled) {
        const isUserHuman = await verifyCloudflareTurnstileToken(captchaToken, remoteIp, secretKey);
        if (!isUserHuman) {
            console.warn({ 'status': 403, 'message': 'CAPTCHA verification failed', 'originIP': remoteIp });
            req.flash('error', 'CAPTCHA verification failed, please try again.');
            return res.status(403).redirect(`/posts/${existingPost.uniqueId}`);
        }
    }

    if (!commenterName || !commentBody) {
        console.error(400, 'Invalid comment data');
        req.flash('error', 'Invalid comment data, please ensure all fields are filled out.');
        return res.status(400).redirect(`/posts/${existingPost.uniqueId}`);
    }
    if (commentBody.length > 500 || commenterName.length > 50 || commenterName.length < 3 || commentBody.length < 1) {
        console.error(400, 'Invalid comment data', 'Size mismatch');
        req.flash('error', 'Invalid comment data, please ensure comment length is between 1 and 500 characters and commenter name length is between 3 and 50 characters.');
        return res.status(400).redirect(`/posts/${existingPost.uniqueId}`);
    }

    try {
        if (!existingPost.isApproved) {
            console.error({ "error": 403, "message": 'Post is not approved', "Post_Id": existingPost.uniqueId });
            return res.status(403).redirect(`/404`);
        }

        const sanitizedCommentName = sanitizeHtml(commenterName);
        const sanitizedCommentBody = sanitizeHtml(commentBody);

        const newComment = new comment({
            postId: postId,
            commenterName: sanitizedCommentName,
            commentBody: sanitizedCommentBody,
            commentTimestamp: Date.now()
        });
        await newComment.save();
        if (process.env.NODE_ENV === 'production') {
            console.log({ "status": "200", "message": "Comment added successfully", "CommenterName": newComment.commenterName });
        } else {
            console.log({ "status": "200", "message": "Comment added successfully", "comment": newComment });
        }
        req.flash('success', 'Comment submitted successfully');
        res.status(200).redirect(`/posts/${existingPost.uniqueId}`);
    } catch (error) {
        console.error('Error adding comment:', error);
        if (process.env.NODE_ENV === 'production') {
            console.error({ "status": "500", "message": "Unable to add comment at this time" });
        } else {
            console.error({ "status": "500", "message": "Error adding comment at this time", "error": error.message });
        }
        req.flash('error', 'Unable to add comment at this time, contact the webmaster. Internal Server Error');
        res.status(500).redirect(`/posts/${existingPost.uniqueId}`);
    }

});

/**
 * @route POST /posts/delete-comment/:commentId
 * @description Deletes a comment from a post if the requesting user has sufficient privileges.
 *              Only users with ADMIN or MODERATOR privilege levels are authorized to delete comments.
 *              Validates comment existence, checks user authorization, logs all operations, and provides
 *              flash feedback with redirection.
 * 
 * @middleware
 * @chain genericAdminRateLimiter - Prevents excessive comment deletion attempts
 * 
 * @params
 * @param {string} commentId - MongoDB `_id` of the comment to delete (route parameter)
 * 
 * @validation
 * @check commentId must correspond to an existing comment
 * @check currentUser must have ADMIN or MODERATOR privilege
 * 
 * @process
 * @step Fetches comment by ID from MongoDB
 * @step Validates user privileges using `getUserFromCookieToken`
 * @step Deletes the comment from the database if authorized
 * @step Logs success or failure, including user information and environment-specific details
 * @step Sets flash messages for user feedback
 * @step Redirects to the original post page or `/404` on failure
 * 
 * @response
 * @success {200} Redirects back to `/post/:postId` with flash message on successful deletion
 * @failure {403} Redirects to `/admin` if the user is unauthorized
 * @failure {404} Redirects to `/404` if comment does not exist
 * @failure {500} Redirects back to the post page with flash message if deletion fails due to server error
 * 
 * @security
 * @access Restricted to users with WEBMASTER or MODERATOR privileges
 * @rateLimited Prevents abuse via repeated deletion requests
 * @csrfToken Must be submitted via site forms
 * 
 * @logging
 * @logs all deletion attempts including:
 *       - Comment ID
 *       - User performing the action
 *       - Status (success/failure)
 *       - Errors with full details in development environment
 * 
 * @access Private (Admin or Moderator only)
 */
router.post('/posts/delete-comment/:commentId', genericAdminRateLimiter, async (req, res) => {
    const { commentId } = req.params;
    try {
        // verify if the comment exists before deleting. If not, redirect to the post page. 404 status to be logged in console
        const thisComment = await comment.findById(commentId);
        if (!thisComment) {
            console.error({ "status": "404", "message": "No comment found", "commentid": commentId });;
            return res.status(404).redirect(`/404`);
        }
        // check if user is authorized to delete the comment
        const currentUser = await getUserFromCookieToken(req);
        const isCurrentUserAModOrAdmin = currentUser && (currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.WEBMASTER || currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.MODERATOR);
        if (!isCurrentUserAModOrAdmin) {
            console.error({ "status": "403", "message": "Unauthorized to delete comment" });
            return res.status(403).redirect('/admin');
        }

        await thisComment.deleteOne()
        console.log({ "status": "200", "message": "Comment deleted successfully", user: currentUser.username });
        req.flash('info', `Comment deleted successfully by ${currentUser.username}`);
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 8:', req.session);
        }
        // Get the post to find its uniqueId for proper redirect
        const thisPost = await post.findById(thisComment.postId);
        const redirectUrl = thisPost ? `/posts/${thisPost.uniqueId}` : '/404';
        return res.status(200).redirect(redirectUrl);

    } catch (err) {
        console.error({ "status": "500", "message": "Error deleting comment", "error": err.message });
        req.flash('error', 'Error deleting comment, contact the webmaster. Internal Server Error');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 9:', req.session);
        }
        if (thisComment && thisComment.postId) {
            // Get the post to find its uniqueId for proper redirect
            try {
                const thisPost = await post.findById(thisComment.postId);
                const redirectUrl = thisPost ? `/posts/${thisPost.uniqueId}` : '/404';
                return res.status(500).redirect(redirectUrl);
            } catch (postErr) {
                return res.status(500).redirect('/404');
            }
        } else {
            return res.status(404).redirect('/404');
        }
    }

});

/**
 * @route GET /advanced-search
 * @description Renders the Advanced Search page for the blogging site.
 *              Provides an interface for performing keyword, title, author, and tag-based searches
 *              with advanced filtering options. Injects site configuration and CSRF token for secure form submission.
 * 
 * @middleware
 * @chain genericGetRequestRateLimiter - Prevents excessive requests to the search page
 * 
 * @response
 * @success {200} Renders `advanced-search` EJS view with:
 *           @property {Object} locals - Page metadata including:
 *                   @subprop {string} title - Page title ("Advanced Search - [Site Name]")
 *                   @subprop {string} description - Page description
 *                   @subprop {Object} config - Site-wide configuration
 *           @property {string} csrfToken - CSRF protection token for secure form submission
 * 
 * @security
 * @csrf Protected form
 * @rateLimited Against excessive requests
 * 
 * @access Public
 */
router.get('/advanced-search', genericGetRequestRateLimiter, (req, res) => {
    const locals = {
        title: "Advanced Search" + ' - ' + (res.locals.siteConfig.siteName || 'Project Walnut'),
        description: "Advanced Search page",
        config: res.locals.siteConfig
    }
    res.render('advanced-search', {
        locals,
        csrfToken: req.csrfToken()
    });
});

/**
 * @route GET /users/:username
 * @description Displays the public profile page of a specific user. 
 *              The username from the URL parameter is sanitized and validated before querying the database.
 *              Renders the profile page with selected user details, including sanitized name, portfolio link, 
 *              and HTML-formatted description. Site configuration and CSRF token are injected for secure page rendering.
 * 
 * @middleware
 * @chain genericGetRequestRateLimiter - Prevents excessive requests to the user profile page.
 * 
 * @request
 * @params {string} username - The username of the user whose profile is to be displayed.
 * 
 * @validation
 * @check Username is sanitized using a strict filter to prevent XSS.
 * @validate Username matches the allowed regex pattern defined in CONSTANTS.USERNAME_REGEX.
 * @sanitize User's name and description fields before rendering.
 * @sanitize Validates the portfolio link to ensure proper URL format.
 * 
 * @response
 * @success {200} Renders `users` EJS view with:
 *           @property {Object} locals - Page metadata including:
 *                   @subprop {string} title - Page title ("About [Username]")
 *                   @subprop {string} description - Description of the page
 *                   @subprop {Object} config - Site-wide configuration
 *           @property {Object} sanitizedUserDetails - User-specific information:
 *                   @subprop {string} name - Sanitized display name
 *                   @subprop {string} markdownDescriptionBody - HTML description of user
 *                   @subprop {string} socialLink - Validated portfolio link
 *                   @subprop {Date} lastUpdated - Last profile update timestamp
 *           @property {string} csrfToken - CSRF protection token for secure form submission
 * 
 * @failure {302} Redirects to home page with flash message when:
 *           @case Username is invalid or fails regex validation
 *           @case User does not exist in the database
 *           @case Any internal server error occurs
 * 
 * @security
 * @csrf Protected form (CSRF token injected)
 * @rateLimited Against excessive profile page requests
 * 
 * @access Public
 */
router.get('/users/:username', genericGetRequestRateLimiter, async (req, res) => {
    try {
        const sanitizedUsername = sanitizeHtml(String(req.params.username).trim(), CONSTANTS.SANITIZE_FILTER);
        if (!CONSTANTS.USERNAME_REGEX.test(sanitizedUsername)) {
            throw new Error("Invalid Username");
        }
        const selectedUser = await user.findOne({ username: sanitizedUsername });
        if (!selectedUser) {
            req.flash('error', 'User does not exist');
            return res.redirect('/');
        }

        const sanitizedName = sanitizeHtml(String(selectedUser.name).trim(), CONSTANTS.SANITIZE_FILTER)
        const sanitizedUserDetails = {
            name: sanitizedName,
            markdownDescriptionBody: selectedUser.htmlDesc ? selectedUser.htmlDesc : CONSTANTS.EMPTY_STRING,
            socialLink: utils.isValidURI(selectedUser.portfolioLink) ? selectedUser.portfolioLink : CONSTANTS.EMPTY_STRING,
            lastUpdated: selectedUser.modifiedAt
        }

        const locals = {
            title: 'About ' + sanitizedName,
            description: 'User profile page for ' + sanitizedName,
            config: res.locals.siteConfig,
        }

        res.render('users', {
            locals,
            sanitizedUserDetails,
            csrfToken: req.csrfToken()
        });
    } catch (error) {
        req.flash('error', 'Internal server error');
        console.error(error);
        return res.redirect('/');
    }
});

/**
 * @route GET /healthz
 * @description
 * Performs a comprehensive health check for the application, verifying the operational
 * status of the **server**, **MongoDB connection**, **site configuration cache**, and **post cache**.
 * Additionally, it reports runtime diagnostics such as uptime, Node.js version,
 * environment mode, and memory usage.
 *
 * This route is public and intended primarily for uptime monitors, load balancers,
 * and orchestration systems to ensure the API is healthy and responsive.
 *
 * @middleware
 * @chain genericGetRequestRateLimiter - Prevents excessive polling or endpoint abuse.
 *
 * @access Public
 *
 * @returns {200} Service is healthy. Returns a JSON object including:
 *  - `status`: "ok"
 *  - `timestamp`: ISO string of current time
 *  - `uptimeSeconds`: Process uptime in seconds
 *  - `environment`: Current environment (hidden in production)
 *  - `nodeVersion`: Node.js version (hidden in production)
 *  - `database`: Connection status ("connected" | "disconnected")
 *  - `siteConfigCache`: Availability of config cache system
 *  - `postCacheStatus`: Availability of post cache
 *  - `postCacheSize`: Cache size details `{ maxCacheSize, cacheSize }`
 *  - `memory`: `{ rss, heapUsed, heapTotal }` in MB
 *
 * @returns {503} Service degradation. Returned when a critical dependency
 * (e.g., database) is unavailable or not connected.
 *
 * @returns {500} Unexpected internal server error, typically due to
 * unhandled exceptions during diagnostics or status collection.
 *
 * @security
 * - CSRF not required (read-only route)
 * - Protected via rate limiter
 *
 * @logging
 * - Logs connection and cache issues for debugging
 * - Logs internal errors on failure response
 */
router.get('/healthz', genericGetRequestRateLimiter, async (req, res) => {
    try {
        const dbStatus = mongoose.connection.readyState === 1 ? 'connected' : 'disconnected';
        if (dbStatus !== 'connected') {
            return res.status(503).json({
                status: 'error',
                message: 'Database connection not established',
                timestamp: new Date().toISOString(),
                database: dbStatus,
            });
        }

        const configCacheStatus = (typeof getCacheStatus === 'function') ? getCacheStatus() : 'unavailable';
        const postCacheStatus = (typeof postCache.getCacheSize === 'function') ? 'available' : 'unavailable';

        const memoryUsage = process.memoryUsage();
        const memory = {
            rss: (memoryUsage.rss / 1024 / 1024).toFixed(2),
            heapUsed: (memoryUsage.heapUsed / 1024 / 1024).toFixed(2),
            heapTotal: (memoryUsage.heapTotal / 1024 / 1024).toFixed(2),
        };

        const environment = process.env.NODE_ENV !== 'production' ? process.env.NODE_ENV : 'hidden';
        const nodeVersion = process.env.NODE_ENV !== 'production' ? process.version : 'hidden';

        res.status(200).json({
            status: 'ok',
            timestamp: new Date().toISOString(),
            uptimeSeconds: process.uptime(),
            environment: environment,
            nodeVersion: nodeVersion,
            database: dbStatus,
            siteConfigCache: configCacheStatus,
            postCacheStatus: postCacheStatus,
            postCacheSize: postCacheStatus === 'available' ? postCache.getCacheSize() : 'hidden',
            memory,
        });
    } catch (error) {
        console.error('Health check failed:', error);
        res.status(500).json({
            status: 'error',
            message: 'Health check failed',
            error: error.message,
            timestamp: new Date().toISOString(),
        });
    }
});

module.exports = router;
