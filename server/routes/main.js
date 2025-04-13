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

const jwtSecretKey = process.env.JWT_SECRET;
const { PRIVILEGE_LEVELS_ENUM, isWebMaster } = require('../../utils/validations');
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

router.use(fetchSiteConfig);

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
        let page = req.query.page || 1;

        const data = await post.aggregate([
            { $match: { isApproved: true } },
            { $sort: { createdAt: -1 } }
        ]).skip(perPage * page - perPage).limit(perPage).exec();

        const count = await post.countDocuments({ isApproved: true });
        const nextPage = parseInt(page) + 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);


        res.render('index', {
            locals,
            data,
            current: page,
            nextPage: hasNextPage ? nextPage : null
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
        locals
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
        locals
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
        let captchaError = "";
        if (req.query.captchaFailed) {
            captchaError = 'H-Hey! What do you think you’re doing?! Just barging in without passing the CAPTCHA… Typical bot behavior! I-I’m not saying I care or anything, but real users should know better!<br/>If by some *miracle* you’re actually a human and not some sneaky little script, then... ugh, fine. Contact the webmaster or whatever. But don’t expect me to go easy on you next time! Baka!';
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
                currentUser: isCurrentUserAModOrAdmin,
                success_msg: req.flash('success_msg'),
                info: req.flash('info'),
                error: req.flash('error')
            });
        } else {
            res.redirect('/404');
        }

    } catch (error) {
        console.error('Post Fetch error', error);
        res.status(404).render('404', {
            locals: {
                title: "404 - Page Not Found",
                description: "The page you're looking for doesn't exist.",
                config: res.locals.siteConfig
            }
        });
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
 * POST /
 * Search: Search term
 */
router.post('/search', async (req, res) => {
    try {

        let searchLimit = res.locals.siteConfig.searchLimit;
        let searchTerm = req.body.searchTerm;
        searchTerm = searchTerm.trim().replace(/[<>]/g, '');
        if (!searchTerm || typeof searchTerm !== 'string') {
            return res.status(400).json({ error: 'Invalid search term' });
        }
        if (searchTerm.trim().length == 0) {
            return res.status(400).json({ error: 'Search term cannot be empty' });
        }
        if (searchTerm.trim().length > 100) {
            return res.status(400).json({ error: 'Search term is too long' });
        }
        const searchNoSpecialChar = searchTerm.replace(/[^a-zA-Z0-9 ]/g, "");
        console.log(new Date(), " - Simple Search - ", searchTerm, " - regex search: ", searchNoSpecialChar);

        const locals = {
            title: "Search - " + searchTerm,
            description: "Simple Search Page",
            config: res.locals.siteConfig
        }

        const data = await post.find(
            {
                $and: [
                    { $text: { $search: searchNoSpecialChar } },
                    { isApproved: true }
                ]
            },
            { score: { $meta: 'textScore' } }
        )
            .sort({ score: { $meta: 'textScore' } })
            .limit(searchLimit);

        res.render('search', { data, locals, searchTerm: searchTerm });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).render('error', {
            locals: {
                title: 'Error'
            },
            error: 'Unable to perform search at this time',
            config: res.locals.siteConfig
        });
    }
});

/**
 * POST
 * /posts/post-comments
 * Add comments to a post
 */
router.post('/post/:id/post-comments', async (req, res) => {
    const { postId, commenterName, commentBody } = req.body;
    const siteConfig = res.locals.siteConfig;
    if (!siteConfig.isCommentsEnabled) {
        console.error({ "error": "403", "message": "Comments are disabled or Cloudflare keys are not set" });
        req.flash('error', 'Comments are disabled or Cloudflare keys are not set');
        console.log('Session after flash0:', req.session);
        return res.status(403).redirect(`/post/${postId}`);
    }

    if (siteConfig.isCaptchaEnabled && (!siteConfig.cloudflareSiteKey || !siteConfig.cloudflareServerKey)) {
        console.error(403, 'CAPTCHA is enabled but Cloudflare keys are not set');
        req.flash('error', 'CAPTCHA config error, contact the webmaster.' );
        console.log('Session after flash1:', req.session);
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
            console.log('Session after flash2:', req.session);
            return res.status(403).redirect(`/post/${postId}`);
        }
    }

    if (!commenterName || !commentBody) {
        console.error(400, 'Invalid comment data');
        req.flash('error', 'Invalid comment data, please ensure all fields are filled out.');
        console.log('Session after flash3:', req.session);
        return res.status(400).redirect(`/post/${postId}`);
    }
    if (commentBody.length > 500 || commenterName.length > 50 || commenterName.length < 3 || commentBody.length < 1) {
        console.error(400, 'Invalid comment data', 'Size mismatch');
        req.flash('error', 'Invalid comment data, please ensure comment length is between 1 and 500 characters and commenter name length is between 3 and 50 characters.');
        console.log('Session after flash4:', req.session);
        return res.status(400).redirect(`/post/${postId}`);
    }

    try {

        //verify if post exists before adding comment. If not, return 404. 404 status code indicates the requested resource was not found on the server. 401 status code
        const existingPost = await post.findById(postId);
        if (!existingPost) {
            console.error({"error": 404, "message": 'No post found', "Post_Id": postId});
            return res.status(404).redirect('/404');
        }

        if (!existingPost.isApproved) {
            console.error({"error": 403, "message": 'Post is not approved', "Post_Id": existingPost._id});
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
        req.flash('success_msg', 'Comment submitted successfully');
        console.log('Session after flash5:', req.session);
        res.status(200).redirect(`/post/${postId}`);
    } catch (error) {
        console.error('Error adding comment:', error);
        if (process.env.NODE_ENV === 'production') {
            console.error({ "status": "500", "message": "Unable to add comment at this time" });
        } else {
            console.error({ "status": "500", "message": "Error adding comment at this time", "error": error.message });
        }
        req.flash('error', 'Unable to add comment at this time, contact the webmaster. Internal Server Error' );
        console.log('Session after flash6:', req.session);
        res.status(500).redirect(`/post/${postId}`);
    }

});

/**
 * POST
 * /posts/post-comments/:commentId
 * Delete a comment from a post if the User is Authorized (Only Admin or Moderator)
 */
router.post('/post/delete-comment/:commentId', async (req, res) => {
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
        console.log('Session after flash7:', req.session);
        res.redirect(`/post/${thisComment.postId}`);

    } catch (err) {
        console.error({ "status": "500", "message": "Error deleting comment", "error": err.message });
        return res.status(500).json({ "status": "500", "message": "Error deleting comment" });
    }

})


module.exports = router;
