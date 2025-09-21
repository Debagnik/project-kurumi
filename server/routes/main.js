const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();
const post = require('../models/posts');
const siteConfig = require('../models/config');
const user = require('../models/user');
const comment = require('../models/comments');
const csrf = require('csurf');
const verifyCloudflareTurnstileToken = require('../../utils/cloudflareTurnstileServerVerify.js');
const sanitizeHtml = require('sanitize-html');

const { genericOpenRateLimiter, genericAdminRateLimiter, commentsRateLimiter, genericGetRequestRateLimiter } = require('../../utils/rateLimiter');

const jwtSecretKey = process.env.JWT_SECRET;
const { PRIVILEGE_LEVELS_ENUM, isWebMaster, parseTags } = require('../../utils/validations');
/**
 * Site config Middleware
 */
const fetchSiteConfig = async (req, res, next) => {
    try {
        const config = await siteConfig.findOne();
        if (!config) {
            console.warn('Site config is not available in database');
            res.locals.siteConfig = {};
        } else {
            res.locals.siteConfig = config;
        }
        next();
    } catch (error) {
        console.error("Critical: Site Config Fetch error", error.message);
        return res.status(500).render('error', {
            locals: {
                title: 'Configuration Error',
                description: 'Unable to load site configuration'
            }
        });
    }
}

router.use(genericOpenRateLimiter, fetchSiteConfig);

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
 * GET /api/test/getCsrfToken
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
 * GET /
 * HOME
 */
router.get('', async (req, res) => {

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
 * GET /about
 * About
 */
router.get('/about', (req, res) => {
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
 * GET /contact
 * Contact
 */
router.get('/contact', (req, res) => {
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
 * GET /
 * Posts :id
 */
router.get('/post/:id', async (req, res) => {
    try {
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
            data.author = 'Anonymous'
        } else {
            data.author = postAuthor.name;
        }

        const isCaptchaEnabled = res.locals.siteConfig.isCaptchaEnabled && !!res.locals.siteConfig.cloudflareSiteKey && !!res.locals.siteConfig.cloudflareServerKey;
        const isCurrentUserAModOrAdmin = currentUser && (currentUser.privilegeLevel === PRIVILEGE_LEVELS_ENUM.ADMIN || currentUser.privilegeLevel === PRIVILEGE_LEVELS_ENUM.MODERATOR);
        if (currentUser || data.isApproved) {
            res.render('posts', {
                locals,
                data,
                csrfToken: req.csrfToken(),
                isCaptchaEnabled,
                commentsData: await getCommentsFromPostId(data._id),
                currentUser: isCurrentUserAModOrAdmin
            });
        } else {
            res.redirect('/404');
        }

    } catch (error) {
        console.error('Post Fetch error', error);
        res.status(404).redirect('/404');
    }
});

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

const getCommentsFromPostId = async (postId) => {
    try {
        const comments = await comment.find({ postId }).sort({ commentTimestamp: -1 });
        return comments;
    } catch (error) {
        console.error('Comment Fetch error', postId, error.message);
        return [];
    }
}

/**
 * @route POST /search
 * @description Handles simple and advanced blog post search. Supports keyword, title, author, and tags.
 *              Falls back to regex search in advanced mode if no results are found.
 * @access Public
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
        const tagArray = parseTags(tags);

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
 * POST
 * /posts/post-comments
 * Add comments to a post
 */
router.post('/post/:id/post-comments', commentsRateLimiter, async (req, res) => {
    const { postId, commenterName, commentBody } = req.body;
    const siteConfig = res.locals.siteConfig;
    if (!siteConfig.isCommentsEnabled) {
        console.error({ "error": "403", "message": "Comments are disabled or Cloudflare keys are not set" });
        req.flash('error', 'Comments are disabled or Cloudflare keys are not set');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 1:', req.session);
        }
        return res.status(403).redirect(`/post/${postId}`);
    }

    if (siteConfig.isCaptchaEnabled && (!siteConfig.cloudflareSiteKey || !siteConfig.cloudflareServerKey)) {
        console.error(403, 'CAPTCHA is enabled but Cloudflare keys are not set');
        req.flash('error', 'CAPTCHA config error, contact the webmaster.');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 2:', req.session);
        }
        return res.status(403).redirect(`/post/${postId}`);
    }

    const captchaToken = req.body['cf-turnstile-response'];
    const remoteIp = req.ip;
    const secretKey = siteConfig.cloudflareServerKey;
    if (siteConfig.isCaptchaEnabled) {
        const isUserHuman = await verifyCloudflareTurnstileToken(captchaToken, remoteIp, secretKey);
        if (!isUserHuman) {
            console.warn({ 'status': 403, 'message': 'CAPTCHA verification failed', 'originIP': remoteIp });
            req.flash('error', 'CAPTCHA verification failed, please try again.');
            if (process.env.NODE_ENV !== 'production') {
                console.log('Session after flash 3:', req.session);
            }
            return res.status(403).redirect(`/post/${postId}`);
        }
    }

    if (!commenterName || !commentBody) {
        console.error(400, 'Invalid comment data');
        req.flash('error', 'Invalid comment data, please ensure all fields are filled out.');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 4:', req.session);
        }
        return res.status(400).redirect(`/post/${postId}`);
    }
    if (commentBody.length > 500 || commenterName.length > 50 || commenterName.length < 3 || commentBody.length < 1) {
        console.error(400, 'Invalid comment data', 'Size mismatch');
        req.flash('error', 'Invalid comment data, please ensure comment length is between 1 and 500 characters and commenter name length is between 3 and 50 characters.');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 5:', req.session);
        }
        return res.status(400).redirect(`/post/${postId}`);
    }

    try {

        //verify if post exists before adding comment. If not, return 404. 404 status code indicates the requested resource was not found on the server. 401 status code
        const existingPost = await post.findById(postId);
        if (!existingPost) {
            console.error({ "error": 404, "message": 'No post found', "Post_Id": postId });
            return res.status(404).redirect('/404');
        }

        if (!existingPost.isApproved) {
            console.error({ "error": 403, "message": 'Post is not approved', "Post_Id": existingPost._id });
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
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 6:', req.session);
        }
        res.status(200).redirect(`/post/${postId}`);
    } catch (error) {
        console.error('Error adding comment:', error);
        if (process.env.NODE_ENV === 'production') {
            console.error({ "status": "500", "message": "Unable to add comment at this time" });
        } else {
            console.error({ "status": "500", "message": "Error adding comment at this time", "error": error.message });
        }
        req.flash('error', 'Unable to add comment at this time, contact the webmaster. Internal Server Error');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 7:', req.session);
        }
        res.status(500).redirect(`/post/${postId}`);
    }

});

/**
 * POST
 * /posts/post-comments/:commentId
 * Delete a comment from a post if the User is Authorized (Only Admin or Moderator)
 */
router.post('/post/delete-comment/:commentId', genericAdminRateLimiter, async (req, res) => {
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
        const isCurrentUserAModOrAdmin = currentUser && (currentUser.privilegeLevel === PRIVILEGE_LEVELS_ENUM.ADMIN || currentUser.privilegeLevel === PRIVILEGE_LEVELS_ENUM.MODERATOR);
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
        return res.status(200).redirect(`/post/${thisComment.postId}`);

    } catch (err) {
        console.error({ "status": "500", "message": "Error deleting comment", "error": err.message });
        req.flash('error', 'Error deleting comment, contact the webmaster. Internal Server Error');
        if (process.env.NODE_ENV !== 'production') {
            console.log('Session after flash 9:', req.session);
        }
        if (thisComment.postId) {
            return res.status(500).redirect(`/post/${thisComment.postId}`);
        } else {
            return res.status(404).redirect('/404');
        }
    }

});

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

module.exports = router;
