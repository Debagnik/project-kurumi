const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const csrf = require('csurf');
const sanitizeHtml = require('sanitize-html');
const marked = require('marked');

const router = express.Router();
const post = require('../models/posts');
const user = require('../models/user');
const siteConfig = require('../models/config');

const { PRIVILEGE_LEVELS_ENUM, isWebMaster, isValidURI, isValidTrackingScript, parseTags } = require('../../utils/validations');

const openRouterIntegration = require('../../utils/openRouterIntegration');
const { aiSummaryRateLimiter, authRateLimiter, genericAdminRateLimiter, genericGetRequestRateLimiter } = require('../../utils/rateLimiter');


const jwtSecretKey = process.env.JWT_SECRET;
const adminLayout = '../views/layouts/admin';
const resettedPassword = 'Qm9jY2hpIHRoZSBSb2Nr';


if (!jwtSecretKey) {
  throw new Error('JWT_SECRET is not set in Environment variable');
}

// adding admin CSRF protection middleware
const csrfProtection = csrf({ cookie: true });
router.use(csrfProtection);

/**
 * Checks login middleware
 */
const authToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.redirect('/admin');
  }

  try {
    const decoded = jwt.verify(token, jwtSecretKey);
    req.userId = decoded.userId;
    next();
  } catch (error) {
    console.error('Invalid token', error);
    req.flash('error', error.message);
    return res.redirect('/admin');
  }
}

/**
 * Site config Middleware
 */
const fetchSiteConfig = async (req, res, next) => {
  try {
    const config = await siteConfig.findOne();
    if (!config) {
      console.warn('Site config is not available');
    }
    res.locals.siteConfig = config || {};
  } catch (error) {
    console.error("Site Config Fetch error", error.message);
    res.locals.siteConfig = {};
  }
  next();
};


router.use(fetchSiteConfig);

/**
 * Post add/edit markdown function
 */
function markdownToHtml(markdownString) {
  try {
    // convert markdown string to HTML string
    let htmlString = marked.parse(markdownString);

    // sanitize HTML string to prevent XSS attacks
    htmlString = sanitizeHtml(htmlString, {
      allowedTags: sanitizeHtml.defaults.allowedTags.concat(['img']),
      allowedAttributes: {
        ...sanitizeHtml.defaults.allowedAttributes,
        img: ['src', 'alt', 'title']
      }
    });
    return htmlString.replace(/<(\/?)h([1-3])>/g, (match, p1, p2) => {
      const newLevel = parseInt(p2) + 1;
      return `<${p1}h${newLevel}>`;
    });
  } catch (error) {
    console.error("Markdown to HTML conversion error", error.message);
    throw new Error('Failed to process markdown content');
  }
}


//Routes
/**
 * @route GET /admin
 * @description Admin login page. Redirects to /dashboard if user is already authenticated.
 * @access Public
 */
router.get('/admin', async (req, res) => {
  try {
    const locals = {
      title: "Admin Panel",
      description: "Admin Panel",
      config: res.locals.siteConfig
    }
    res.render('admin/index', {
      locals,
      layout: adminLayout,
      csrfToken: req.csrfToken(),
      isWebMaster: false
    });
  } catch (error) {
    console.error("Admin Page error", error.message);
    res.status(500).send('Internal Server Error');
  }
});

/**
 * POST /
 * ADMIN - Register
 */
router.post('/register', genericAdminRateLimiter, async (req, res) => {
  try {
    const { username, password, name, confirm_password } = req.body;

    //check for empty field
    if (!name || !username || !password || !confirm_password) {
      console.error(401, 'empty mandatory fields');
      throw new Error('One or more mandatory fields are missing');
    }

    // check is username is of proper format defined in regex pattern
    const usernameRegex = /^[a-zA-Z0-9\-\_\.\+\@]+$/;
    const usernameErrorMessage = 'Username can only contain letters, numbers, hyphens, underscores, dots, plus signs, and at-symbols!'
    if (!usernameRegex.test(username)) {
      const env = process.env.NODE_ENV;
      if (env && env.toLowerCase() === "production") {
        console.error(400, 'Invalid username format');
      } else {
        console.error(400, 'Invalid username format', username);
      }
      throw new Error(usernameErrorMessage);
    }

    // checking for existing user
    const existingUser = await user.findOne({ username })
    if (existingUser) {
      console.error(409, 'Username already exists');
      throw new Error('Username already Exists, try a new username');
    }

    //check password and confirm password match
    if (!(password === confirm_password)) {
      console.error('Password and confirm passwords do not match');
      throw new Error('Passwords and Confirm Password do not match!');
    }

    if (!isStrongPassword(password)) {
      throw new Error('Password is too weak. It should be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, one number, and one special character.');
    }

    //registration logic
    if (res.locals.siteConfig.isRegistrationEnabled) {
      const hashedPassword = await bcrypt.hash(password, 10);
      try {
        const newUser = await user.create({ username, password: hashedPassword, name });
        console.log('User created', newUser, 201);
        req.flash('success', `new user ${username} is created, try signing in`)
        res.redirect('/admin');
      } catch (error) {
        console.error({
          status: 500,
          message: 'Internal server error',
          reason: error.message
        });
        req.flash('error', error.message);
        res.redirect('/admin');
      }
    } else {
      console.warn(`Someone with username ${username} tryied registering when it is turned off`);
      req.flash('info', 'Registration not enabled, Contact with Site admin, User not created, This incedent will be reported');
      res.redirect('/admin');
    }
  } catch (error) {
    console.error('errors during registration', error);
    req.flash('error', error.message);
    res.redirect('/admin');
  }
});

/**
 * POST
 * Admin - Check Login
 */
router.post('/admin', authRateLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    //checks if the username or passwords are not empty
    if (!username || !password) {
      throw new Error('Username and Passwords are mandatory');
    }

    //checks if the user exists
    const currentUser = await user.findOne({ username });
    if (!currentUser) {
      console.error('invalid Username for user: ', username);
      throw new Error('Either username or password dont match, Invalid credentials');
    }

    if (currentUser.isPasswordReset) {
      console.error('Login Disabled for this Username:', username);
      throw new Error('Login Disabled for this Username, Contact Webmaster');
    }

    //password validity check
    const isPasswordValid = await bcrypt.compare(password, currentUser.password);
    if (!isPasswordValid) {
      console.error('invalid password for user: ', username);
      throw new Error('Either username or password dont match, Invalid credentials');
    }

    //adds session
    const token = jwt.sign({ userId: currentUser._id }, jwtSecretKey);
    res.cookie('token', token, { httpOnly: true });
    console.log("Successful Log In", (process.env.NODE_ENV && process.env.NODE_ENV.toLowerCase() !== "production") ? username : '');
    req.flash('success', `Sign in successful, welcome ${currentUser.name}`);
    res.redirect('/dashboard');
  } catch (error) {
    //for any other errors
    console.error({
      status: 500,
      message: 'Internal Server Error',
      Reason: error.message
    });
    req.flash('error', error.message);
    res.redirect('/admin');
  }
});

/**
 * GET
 * Admin - Dashboard
 */
router.get('/dashboard', authToken, genericGetRequestRateLimiter, async (req, res) => {
  try {
    const locals = {
      title: 'Admin Dashboard',
      description: 'Dashboard Panel',
      config: res.locals.siteConfig
    };
    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found', req.userId);
      req.flash('error', `I-It's not like I want you to be here or anything! B-But you’re not allowed on this page, okay?! So just go away before I really get mad! Hmph`);
      return res.redirect('/admin');
    }
    let data;
    switch (currentUser.privilege) {
      case PRIVILEGE_LEVELS_ENUM.WRITER:
        data = await post.find({ author: currentUser.username }).sort({ createdAt: -1 });
        break;
      case PRIVILEGE_LEVELS_ENUM.MODERATOR:
        data = await post.find().sort({ createdAt: -1 });
        break;
      case PRIVILEGE_LEVELS_ENUM.WEBMASTER:
        data = await post.find().sort({ createdAt: -1 });
        break;
      default:
        console.error({
          status: 403,
          message: 'Invalid privilage level',
          reason: 'User did not have adequate permission to view this page'
        });
        req.flash('error', 'You do not have adequate permission to view this page, Contact Webmaster');
        return res.status(403).redirect('/admin');
    }

    res.render('admin/dashboard', {
      locals,
      layout: adminLayout,
      currentUser,
      data,
      csrfToken: req.csrfToken(),
      isWebMaster: isWebMaster(currentUser)
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

/**
 * GET
 * Admin - new post
 */
router.get('/admin/add-post', authToken, genericGetRequestRateLimiter, async (req, res) => {
  try {
    const locals = {
      title: 'Add Post',
      description: 'Add Post',
      config: res.locals.siteConfig
    };

    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found', req.userId);
      req.flash('error', `I-It's not like I want you to be here or anything! B-But you’re not allowed on this page, okay?! So just go away before I really get mad! Hmph!`);
      return res.redirect('/admin');
    }

    res.render('admin/add-post', {
      locals,
      layout: adminLayout,
      currentUser,
      csrfToken: req.csrfToken(),
      isWebMaster: isWebMaster(currentUser)
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal Server Error');
  }
});

/**
 * POST
 * Admin - new post
 */
router.post('/admin/add-post', authToken, genericAdminRateLimiter, async (req, res) => {
  try {
    await savePostToDB(req, res);
    req.flash('success', 'New Post Created')
    return res.status(201).redirect('/dashboard');
  } catch (error) {
    console.error({ status: 500, message: 'Internal Server Error', reason: error.message });
    req.flash('error', error.message)
    res.redirect('/dashboard');
  }

});

async function savePostToDB(req, res) {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found');
      throw new Error("User not found while saving post.");
    }

    const currentSiteConfig = await siteConfig.findOne();
    let siteConfigDefaultThumbnail;
    if (!currentSiteConfig) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('Site configuration not found');
      }
      siteConfigDefaultThumbnail = process.env.DEFAULT_POST_THUMBNAIL_LINK
    } else {
      siteConfigDefaultThumbnail = currentSiteConfig.siteDefaultThumbnailUri;
    }

    const defaultThumbnailImageURI = isValidURI(req.body.thumbnailImageURI) ? req.body.thumbnailImageURI : siteConfigDefaultThumbnail

    if (!req.body.title?.trim() || !req.body.markdownbody?.trim() || !req.body.desc?.trim()) {
      console.error('Missing required fields!');
      throw new Error("Title, body, and description are required!");
    }
    const MAX_TITLE_LENGTH = parseInt(process.env.MAX_TITLE_LENGTH) || 50;
    const MAX_DESCRIPTION_LENGTH = parseInt(process.env.MAX_DESCRIPTION_LENGTH) || 1000;
    const MAX_BODY_LENGTH = parseInt(process.env.MAX_BODY_LENGTH) || 100000;
    if (req.body.title.length > MAX_TITLE_LENGTH || req.body.markdownbody.length > MAX_BODY_LENGTH || req.body.desc.length > MAX_DESCRIPTION_LENGTH) {
      console.error('Title, body, and description must not exceed their respective limits!');
      throw new Error('Title, body, and description must not exceed their respective limits!')
    }

    const htmlBody = markdownToHtml(req.body.markdownbody.trim());

    const newPost = new post({
      title: req.body.title.trim(),
      markdownbody: req.body.markdownbody.trim(),
      body: htmlBody,
      author: currentUser.username.trim(),
      tags: parseTags(req.body.tags),
      desc: req.body.desc.trim(),
      thumbnailImageURI: defaultThumbnailImageURI,
      lastUpdateAuthor: currentUser.username.trim(),
      modifiedAt: Date.now()
    });

    await newPost.save();

    console.log('New post added by ', currentUser.username, '\n', newPost);

    return newPost._id.toString();

  } catch (error) {
    throw new Error(`Could not save post data: ${error.message}`);
  }
}

/**
 * GET
 * Admin Edit post
 */
router.get('/edit-post/:id', authToken, genericGetRequestRateLimiter, async (req, res) => {
  try {

    const data = await post.findOne({ _id: req.params.id });

    const locals = {
      title: "Edit Post - " + data.title,
      description: "Post Editor",
      config: res.locals.siteConfig
    };

    const currentUser = await user.findById(req.userId);

    res.render('admin/edit-post', {
      locals,
      data,
      layout: adminLayout,
      csrfToken: req.csrfToken(),
      isWebMaster: isWebMaster(currentUser),
      currentUser: { privilege: currentUser.privilege }
    })

  } catch (error) {
    console.log(error);
    req.flash('error', 'Internal Server Error');
    res.redirect('/dashboard');
  }
});

/**
 * PUT /
 * Admin - Edit Post
*/
router.put('/edit-post/:id', authToken, genericAdminRateLimiter, async (req, res) => {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found', req.userId);
      throw new Error(`No User Found for: ${req.userId}`);
    }
    const currentSiteConfig = await siteConfig.findOne();
    let siteConfigDefaultThumbnail;
    if (!currentSiteConfig) {
      if (process.env.NODE_ENV !== 'production') {
        console.warn('Site configuration not found');
      }
      siteConfigDefaultThumbnail = process.env.DEFAULT_POST_THUMBNAIL_LINK
    } else {
      siteConfigDefaultThumbnail = currentSiteConfig.siteDefaultThumbnailUri;
    }
    const defaultThumbnailImageURI = isValidURI(req.body.thumbnailImageURI) ? req.body.thumbnailImageURI : siteConfigDefaultThumbnail;

    if (!req.body.title?.trim() || !req.body.markdownbody?.trim() || !req.body.desc?.trim()) {
      if (process.env.NODE_ENV !== 'production') {
        console.error('Title, body, and description are missing while editing /post/', req.params.id);
      }
      req.flash('error', 'Title, body, and description are required!, Post is not updated');
      return res.redirect(`/admin/edit-post/${req.params.id}`)
    }

    const MAX_TITLE_LENGTH = parseInt(process.env.MAX_TITLE_LENGTH) || 50;
    const MAX_DESCRIPTION_LENGTH = parseInt(process.env.MAX_DESCRIPTION_LENGTH) || 1000;
    const MAX_BODY_LENGTH = parseInt(process.env.MAX_BODY_LENGTH) || 100000;

    if (req.body.title.length > MAX_TITLE_LENGTH || req.body.markdownbody.length > MAX_BODY_LENGTH || req.body.desc.length > MAX_DESCRIPTION_LENGTH) {
      if (process.env.NODE_ENV !== 'production') {
        console.error('Title, body, and description must not exceed their respective limits while editing /post/', req.params.id);
      }
      req.flash('error', 'Title, body, and description must not exceed their respective limits!, Post is not updated');
      return res.redirect(`/admin/edit-post/${req.params.id}`);

    }
    const htmlBody = markdownToHtml(req.body.markdownbody.trim());

    const updatePostData = {
      title: req.body.title.trim(),
      body: htmlBody,
      markdownbody: req.body.markdownbody.trim(),
      desc: req.body.desc.trim(),
      tags: parseTags(req.body.tags.trim()),
      thumbnailImageURI: defaultThumbnailImageURI,
      modifiedAt: Date.now(),
      lastUpdateAuthor: currentUser.username
    }

    if (currentUser.privilege === PRIVILEGE_LEVELS_ENUM.MODERATOR || currentUser.privilege === PRIVILEGE_LEVELS_ENUM.WEBMASTER) {
      updatePostData.isApproved = req.body.isApproved === 'on'
    }

    await post.findByIdAndUpdate(req.params.id, updatePostData);

    const updatedPost = await post.findById(req.params.id);
    if (!updatedPost) {
      console.error('Failed to update post', req.params.id);
      req.flash('error', 'Something went wrong, Post not updated')
      return res.redirect(`/admin/edit-post/${req.params.id}`);
    }

    req.flash('success', `Successfully updated post with id ${req.params.id}`);
    res.redirect(`/dashboard/`);

  } catch (error) {
    console.log(error);
    req.flash('error', 'Something Went Wrong');
    res.redirect('/dashboard');
  }

});

/**
 * DELETE
 * Admin - Post - Delete
 */
router.delete('/delete-post/:id', authToken, genericAdminRateLimiter, async (req, res) => {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found', req.userId);
      req.flash('error', `User not found/User Logged out`);
      return res.redirect('/admin');
    }

    const postToDelete = await post.findById(req.params.id);
    if (!postToDelete) {
      console.error('Post not found', req.params.id);
      req.flash('error', `post not found`);
      return res.redirect('/dashboard');
    }

    await post.deleteOne({ _id: req.params.id });
    console.log('Post deleted successfully\nDeletion Request: ', currentUser.username, '\nDeleted Post: ', postToDelete);
    req.flash('success', `Post Successfully Deleted with Id ${req.params.id}`);
    res.redirect('/dashboard');
  } catch (error) {
    console.log(error);
    req.flash(`error`, `Something went wrong`);
    res.redirect('/dashboard');
  }
});

/**
 * GET /
 * Admin Logout
*/
router.post('/logout', (req, res) => {
  res.clearCookie('token');
  req.flash('success', `Sucessfully Logged out, Goodbye`);
  res.redirect('/admin');
});

/**
 * GET - Admin Webmaster
 */
router.get('/admin/webmaster', authToken, genericGetRequestRateLimiter, async (req, res) => {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found', req.userId);
      req.flash('error', 'User not found');
      res.redirect('/admin');
    }

    // Check if the user has the necessary privileges
    if (currentUser.privilege !== PRIVILEGE_LEVELS_ENUM.WEBMASTER) {
      req.flash('error', `you don't have sufficient permission/privilage to view this page`);
      return res.redirect('/dashboard');
    }

    const locals = {
      title: "Webmaster Panel",
      description: "Webmaster Administration Panel",
      config: res.locals.siteConfig
    }

    let config = await siteConfig.findOne();
    if (!config) {
      config = new siteConfig({
        isRegistrationEnabled: true,
        siteName: 'Blog-Site',
        lastModifiedBy: 'System',
      });
      await config.save();
    }

    const users = await user.find({ _id: { $ne: currentUser._id } }).sort({ privilege: -1 });

    res.render('admin/webmaster', {
      locals,
      layout: adminLayout,
      currentUser,
      csrfToken: req.csrfToken(),
      isWebMaster: isWebMaster(currentUser),
      config: config,
      users
    });
  } catch (error) {
    console.error("Webmaster Page error", error);
    req.flash('error', 'Something went wrong, Internal server error');
    res.redirect('/dashboard');
  }
});

/**
 * @route POST /edit-site-config
 * @description Updates global site configuration settings. This route is protected and accessible only to users
 *              with `WEBMASTER` privilege. It validates and sanitizes user input, updates the settings in the
 *              database, and handles both the creation and updating of site configuration records.
 * 
 * @middleware authToken - Ensures the request is authenticated and attaches `req.userId`.
 * 
 * @request
 * @body {string} siteName - The name of the site (sanitized).
 * @body {string} siteMetaDataKeywords - Meta keywords for the site (sanitized).
 * @body {string} siteMetaDataAuthor - Author metadata (sanitized).
 * @body {string} siteMetaDataDescription - Site meta description (sanitized).
 * @body {string} googleAnalyticsScript - Google Analytics script (validated).
 * @body {string} inspectletScript - Inspectlet or Microsoft Clarity tracking script (validated).
 * @body {string} siteAdminEmail - Site admin email (validated).
 * @body {string} siteDefaultThumbnailUri - Default thumbnail URI for posts (validated as URL).
 * @body {number} defaultPaginationLimit - Default pagination count (validated).
 * @body {number} searchLimit - Default search result limit (validated).
 * @body {string} homeWelcomeText - Homepage welcome text (sanitized).
 * @body {string} homeWelcomeSubText - Homepage welcome subtext (sanitized).
 * @body {string} homepageWelcomeImage - Homepage image URL (validated as URL).
 * @body {string} copyrightText - Copyright notice (sanitized).
 * @body {string} cloudflareSiteKey - CAPTCHA site key for Cloudflare Turnstile (sanitized).
 * @body {string} cloudflareServerKey - CAPTCHA secret key for Cloudflare Turnstile (sanitized).
 * @body {string} isRegistrationEnabled - 'on' if registration is enabled.
 * @body {string} isCommentsEnabled - 'on' if comments are enabled.
 * @body {string} isCaptchaEnabled - 'on' if CAPTCHA is enabled.
 * 
 * @returns {302} Redirects to /admin/webmaster on success.
 * @returns {400} If any field fails validation.
 * @returns {403} If the user is not authorized.
 * @returns {500} If an internal server error occurs.
 */
router.post('/edit-site-config', authToken, genericAdminRateLimiter, async (req, res) => {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser) {
      console.error('User not found', req.userId);
      throw new Error('User not found');
    }

    if (currentUser.privilege === PRIVILEGE_LEVELS_ENUM.WEBMASTER) {
      // Update site settings in the database
      let globalSiteConfig = await siteConfig.findOne();

      // Validate critical fields
      const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
      if (req.body.siteAdminEmail && !emailRegex.test(req.body.siteAdminEmail)) {
        console.warn('webmaster tried putting invalid email');
        throw new Error('Webmaster tried adding ill-formed email address');
      }
      const paginationLimit = parseInt(req.body.defaultPaginationLimit);
      if (Number.isNaN(paginationLimit) || paginationLimit < 1 || paginationLimit > 100) {
        console.warn('Invalid pagination limit');
        throw new Error('Webmaster tried updating invalid pagination limit')
      }

      const searchLimit = parseInt(req.body.searchLimit);
      if (Number.isNaN(searchLimit) || searchLimit < 1 || searchLimit > 50) {
        console.warn('Invalid search limit');
        throw new Error('Webmaster tried updating invalid pagination limit')
      }


      let validUrl = globalSiteConfig.siteDefaultThumbnailUri;
      if (req.body.siteDefaultThumbnailUri) {
        validUrl = isValidURI(req.body.siteDefaultThumbnailUri) ? req.body.siteDefaultThumbnailUri : process.env.DEFAULT_POST_THUMBNAIL_LINK;
      }
      const registrationEnable = req.body.isRegistrationEnabled === 'on';
      const commentsEnabled = req.body.isCommentsEnabled === 'on';
      const captchaEnabled = req.body.isCaptchaEnabled === 'on';
      const aISummerizerEnabled = req.body.isAISummerizerEnabled === 'on';

      let validHomePageImageUri = globalSiteConfig.homepageWelcomeImage;
      if (req.body.homepageWelcomeImage) {
        validHomePageImageUri = isValidURI(req.body.homepageWelcomeImage) ? req.body.homepageWelcomeImage : validUrl;
      }

      // global site settings helper
      const createConfigObject = (req, currentUser, validUrl, validHomePageImageUri, registrationEnable, commentsEnabled, captchaEnabled, aISummerizerEnabled) => ({
        isRegistrationEnabled: registrationEnable,
        isCommentsEnabled: commentsEnabled,
        isCaptchaEnabled: captchaEnabled,
        siteName: sanitizeHtml(req.body.siteName),
        siteMetaDataKeywords: sanitizeHtml(req.body.siteMetaDataKeywords),
        siteMetaDataAuthor: sanitizeHtml(req.body.siteMetaDataAuthor),
        siteMetaDataDescription: sanitizeHtml(req.body.siteMetaDataDescription),
        googleAnalyticsScript: isValidTrackingScript(req.body.googleAnalyticsScript),
        siteAdminEmail: sanitizeHtml(req.body.siteAdminEmail),
        siteDefaultThumbnailUri: validUrl,
        defaultPaginationLimit: req.body.defaultPaginationLimit,
        lastModifiedDate: Date.now(),
        lastModifiedBy: currentUser.username,
        inspectletScript: isValidTrackingScript(req.body.inspectletScript),
        homeWelcomeText: sanitizeHtml(req.body.homeWelcomeText),
        homeWelcomeSubText: sanitizeHtml(req.body.homeWelcomeSubText),
        homepageWelcomeImage: validHomePageImageUri,
        copyrightText: sanitizeHtml(req.body.copyrightText),
        searchLimit: searchLimit,
        cloudflareSiteKey: sanitizeHtml(req.body.cloudflareSiteKey),
        cloudflareServerKey: sanitizeHtml(req.body.cloudflareServerKey),
        isAISummerizerEnabled: aISummerizerEnabled
      });

      if (!globalSiteConfig) {
        globalSiteConfig = new siteConfig(createConfigObject(req, currentUser, validUrl, validHomePageImageUri, registrationEnable, commentsEnabled, captchaEnabled, aISummerizerEnabled));
        await globalSiteConfig.save();
      } else {
        await siteConfig.findOneAndUpdate({}, createConfigObject(req, currentUser, validUrl, validHomePageImageUri, registrationEnable, commentsEnabled, captchaEnabled, aISummerizerEnabled), { new: true });
      }
      console.log(`Site settings updated successfully by user: ${currentUser.username}`);
      req.flash('success', `Site settings are sucessfully updated`);
      res.redirect('/admin/webmaster');
    } else {
      console.error(`Unauthorised user tried to update site settings`);
      req.flash('error', `you dont have sufficient privilage/permission to update global site settings`);
      req.flash('info', `This incedent will be reported`);
      res.redirect('/dashboard');
    }
  } catch (error) {
    console.error(error);
    req.flash('error', error.message);
    res.redirect('/dashboard');
  }
});

/**
 * DELETE
 * Webmaster - User - Delete
 */
router.delete('/delete-user/:id', authToken, genericAdminRateLimiter, async (req, res) => {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser || currentUser.privilege !== PRIVILEGE_LEVELS_ENUM.WEBMASTER) {
      console.warn('Unauthorized user tried to delete different user', req.userId);
      throw new Error('Unauthorised, User not deleted');
    }

    const userToDelete = await user.findById(req.params.id);
    if (!userToDelete) {
      console.warn('User not found', req.params.id);
      throw new Error('Current user not found');
    }

    //prevent self deletion
    if (currentUser._id.toString() === userToDelete._id.toString()) {
      console.warn({
        status: 403,
        message: 'Invalid Operation',
        reason: 'user tried to delete itself'
      });
      req.flash('error', 'Did you just try to delete yourself');
      req.flash('info', 'Suicide helpline number: 1800-1208-20050');
      res.redirect(`/edit-user/${userToDelete._id}`)
    }

    await user.deleteOne({ _id: req.params.id });
    console.log('User deleted successfully\nDeletion Request: ', currentUser.username, '\nDeleted user: ', userToDelete);
    req.flash('info', `User ${userToDelete.username} is deleted`);
    res.redirect('/admin/webmaster');
  } catch (error) {
    console.error(error);
    req.flash('error', error.message);
    res.redirect('/admin/webmaster');
  }
});


/**
 * GET
 * Webmaster Edit user
 */
router.get('/edit-user/:id', authToken, genericGetRequestRateLimiter, async (req, res) => {
  try {
    const selectedUser = await user.findOne({ _id: req.params.id });
    if (!selectedUser) {
      console.error('User not found', req.params.id);
      throw new Error('User not found');
    }

    const locals = {
      title: "Webmaster - Edit User - " + selectedUser.name,
      description: "User Editor",
      config: res.locals.siteConfig
    };

    const currentUser = await user.findById(req.userId);

    res.render('admin/edit-user', {
      locals,
      selectedUser,
      layout: adminLayout,
      csrfToken: req.csrfToken(),
      isWebMaster: isWebMaster(currentUser),
      showDelete: currentUser.username !== selectedUser.username,
      config: res.locals.siteConfig
    })

  } catch (error) {
    console.error(error);
    req.flash('error', 'Something went wrong, Internal Server Error');
    res.redirect(`/dashboard`);
  }
});

/**
 * @route PUT /edit-user/:id
 * @description Allows a webmaster to update a user's profile details, including privilege level and optionally resetting the user's password.
 *              Only users with `WEBMASTER` privilege can perform this action.
 *
 * @middleware authToken - Verifies authentication and attaches `req.userId`.
 * @middleware genericAdminRateLimiter - Applies rate limiting to prevent abuse.
 *
 * @param {string} req.params.id - The ID of the user to be edited.
 * @param {string} req.body.name - The updated name of the user (must be non-empty and sanitized).
 * @param {string} req.body.privilege - The new privilege level for the user (must be valid).
 * @param {string} [req.body.adminTempPassword] - (Optional) A new temporary password to be set by admin; must be strong if provided.
 *
 * @returns {Redirect} 302 - Redirects to `/admin/webmaster` on success.
 * @returns {Object} 400 - If required fields are missing, invalid, or contain disallowed characters.
 * @returns {Object} 403 - If the requester is not authorized (not a webmaster).
 * @returns {Object} 500 - On internal server error or database issues.
 */
router.put('/edit-user/:id', authToken, genericAdminRateLimiter, async (req, res) => {
  try {
    const currentUser = await user.findById(req.userId);
    if (!currentUser || currentUser.privilege !== PRIVILEGE_LEVELS_ENUM.WEBMASTER) {
      console.warn('Unauthorized user tried to delete different user', req.userId);
      throw new Error('Unauthorized User cannot edit other users');
    }

    const updateUser = await user.findById(req.params.id);
    if (!updateUser) {
      console.warn('User To be updated not found');
      throw new Error('User to be updated not found');
    }

    if (!req.body.name || !req.body.name.trim()) {
      console.warn('Name is a required field');
      throw new Error('Name is a required field');
    }

    let hashedTempPassword = '';
    let hasAdminResettedPassword = false;
    if (req.body.adminTempPassword) {
      hasAdminResettedPassword = true;
      const tempPassword = req.body.adminTempPassword.trim();
      if (!isStrongPassword(tempPassword)) {
        console.warn(`Webmaster User ${currentUser.username} tried resetting password of User ${updateUser.username} with a weak password`);
        throw new Error('Password is not strong enough, Must contain at least 8 characters, must contain a mix of uppercase, lowercase, numeric and special characters');
      }
      hashedTempPassword = await bcrypt.hash(tempPassword, 10);
    }

    const sanitizedName = sanitizeHtml(req.body.name.trim(), {
      allowedTags: [],
      allowedAttributes: {}
    });

    if (sanitizedName !== req.body.name.trim()) {
      console.warn(`Webmaster user ${updateUser.username} tried to add scripts on User's name`);
      req.flash('error', `you cannot add scripts on the user's name`);
      req.flash('info', `This incedent will be reported`);
    }

    const privilageLevel = (!isNaN(parseInt(req.body.privilege)) || !req.body.privilege) ? parseInt(req.body.privilege) : parseInt(updateUser.privilege);
    if (!Object.values(PRIVILEGE_LEVELS_ENUM).includes(parseInt(privilageLevel))) {
      console.warn('Invalid Privilage level');
      throw new Error('Invalid Privilage Level');
    }

    updateUser.name = sanitizedName;
    updateUser.privilege = privilageLevel;
    updateUser.isPasswordReset = hasAdminResettedPassword;
    updateUser.adminTempPassword = hashedTempPassword;
    updateUser.password = !hasAdminResettedPassword ? updateUser.password : resettedPassword;
    updateUser.modifiedAt = Date.now();

    try {
      await updateUser.save();
      console.log('User Updated successfully');
      req.flash('success', 'User Updated Successfully');
      res.redirect('/admin/webmaster');
    } catch (error) {
      console.error('Issue occured while updating user info', error);
      req.flash('error', 'Something went wrong while updating user, please try again');
      return res.redirect(`/edit-user/${req.params.id}`)
    }

  } catch (error) {
    console.log(error);
    req.flash('error', error.message);
    return res.redirect(`/edit-user/${req.params.id}`);
  }
});

/**
 * Checks if a password is strong based on defined criteria.
 *
 * A strong password must:
 * - Be at least 8 characters long
 * - Contain at least one uppercase letter
 * - Contain at least one lowercase letter
 * - Contain at least one number
 * - Contain at least one special character from the set [!@#$%^&*()]
 *
 * @function isStrongPassword
 * @param {string} password - The password string to validate.
 * @returns {boolean} Returns `true` if the password meets all strength requirements, otherwise `false`.
 *
 */
function isStrongPassword(password) {
  const minLength = 8;
  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*()]/.test(password);
  return password.length >= minLength && hasUppercase && hasLowercase && hasNumber && hasSpecialChar;
}

/**
 * @route POST /admin/generate-post-summary
 * @description Generates a summary of a blog post's markdown body using an LLM via OpenRouter.
 * @access Private (Admin only)
 * @middleware
 *    - authToken: Ensures the user is authenticated.
 *    - aiSummaryRateLimiter: Prevents abuse by rate limiting summary generation requests.
 * 
 * @body
 * @param {string} markdownbody - Raw markdown content of the blog post. (Required)
 * 
 * @returns {Object} JSON response
 * @returns {number} code - HTTP-style status code
 * @returns {string} message - HTML-formatted AI-generated summary or error message
 */
router.post('/admin/generate-post-summary', authToken, aiSummaryRateLimiter, async (req, res) => {
  try {
    if (!req.body.markdownbody) {
      return res.status(400).json({
        'code': 400,
        'message': 'Blog Body is a must for generating summary'
      });
    }
    const response = await openRouterIntegration.summarizeMarkdownBody(sanitizeHtml(req.body.markdownbody).trim());
    const htmlResponse = markdownToHtml(response.summary + response.attribute);
    return res.status(200).json({
      'code': 200,
      'message': htmlResponse
    });
  } catch (error) {
    console.error('error generating summary: ', error);
    return res.status(500).json({
      'code': 500,
      'message': 'Internal Server Error'
    });
  }
});

/**
 * @route GET /admin/reset-password
 * @description Renders the password reset page for users who were issued a temporary admin-generated password.
 *              This route displays the form where users can input their temporary and new passwords.
 *
 * @middleware genericGetRequestRateLimiter - Applies rate limiting to avoid abuse of the reset page.
 *
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 *
 * @returns {HTML} 200 - Renders the 'forgot-password' EJS view with CSRF token and site configuration.
 *
 * @view admin/forgot-password.ejs - The view file that contains the password reset form.
 *
 * @locals
 *   {string} title - The title of the page ("Forgot Password").
 *   {string} description - A short description for SEO/meta purposes.
 *   {Object} config - Site configuration object from `res.locals.siteConfig`.
 *   {string} csrfToken - Token to protect against CSRF attacks.
 *   {boolean} isWebMaster - Indicates whether the current user is a webmaster (false in this context).
 *
 */
router.get('/admin/reset-password', genericGetRequestRateLimiter, async (req, res) => {
  try {
    const locals = {
      title: "Forgot Password",
      description: "Password Reset Page",
      config: res.locals.siteConfig
    };

    return res.render('admin/reset-password', {
      locals,
      layout: adminLayout,
      csrfToken: req.csrfToken(),
      isWebMaster: false
    });
  } catch(error){
    console.log(error);
    req.flash('error', 'Internal Server Error');
    return res.redirect('/admin');
  }
});

/**
 * @route POST /admin/reset-password
 * @description Allows a user with a temporary admin-generated password to securely reset their password.
 *              This route is part of the admin interface and is rate-limited.
 *
 * @middleware genericAdminRateLimiter - Applies rate limiting to prevent brute-force attacks.
 *
 * @param {string} req.body.username - The username of the account attempting to reset its password.
 * @param {string} req.body.tempPassword - The temporary password provided by the admin for reset.
 * @param {string} req.body.newPassword - The user's desired new password.
 * @param {string} req.body.confirmPassword - Confirmation of the new password.
 *
 * @returns {Object} 400 - If any required field is missing or if input validation fails.
 * @returns {Object} 401 - If the provided temporary password is incorrect.
 * @returns {Object} 403 - If password reuse is attempted or user is not authorized for reset.
 * @returns {Object} 500 - On internal server errors.
 * @returns {Redirect} 200 - On successful password reset, redirects to /admin.
 *
 * @throws Will return JSON error messages on validation failure or exceptions.
 */
router.post('/admin/reset-password', genericAdminRateLimiter, async (req, res) => {
  try {
    const { username, tempPassword, newPassword, confirmPassword } = req.body;
    if (!username || !tempPassword || !newPassword || !confirmPassword) {
      console.log({ 'status': 400, 'message': 'one or more required feild missing' })
      throw new Error('One or more fields are missing');
    }
    const userModel = await user.findOne({ username: username });
    if (!userModel) {
      throw new Error(`User Does't exist`);
    }
    if (!userModel.isPasswordReset || !userModel.adminTempPassword || userModel.password !== resettedPassword) {
      throw new Error('User profile is not approved for reset by webmaster');
    }

    if (newPassword === tempPassword) {
      throw new Error('User can not reuse temporary Password as their new password');
    }

    if (!isStrongPassword(newPassword)) {
      throw new Error('Password is not strong');
    }

    if (newPassword !== confirmPassword) {
      throw new Error('new Password and confirm password do not match');
    }

    const isPasswordValid = await bcrypt.compare(tempPassword, userModel.adminTempPassword);
    if (!isPasswordValid) {
      console.error(`User: ${username} is trying to reset password with incorrect temp password`, username);
      throw new Error('Either the username or the Temp password combination might be incorrect');
    } else {
      console.log(`User: ${username} has successfully validated temp password`);
      const hashedPassword = await bcrypt.hash(newPassword, 10);
      userModel.password = hashedPassword;
      userModel.isPasswordReset = false;
      userModel.adminTempPassword = '';
      try {
        await userModel.save();
        console.log('user reset successful');
        req.flash('success', 'User password successfully resetted');
        req.flash('info', `login is enabled for user: ${username}, please sign in`);
        return res.status(200).redirect('/admin');
      } catch (error) {
        console.log('error while password reset', error);
        req.flash('error', 'Something went wrong while resetting password, Internal Server Error');
        res.redirect('/admin/reset-password');
      }
    }
  } catch (error) {
    console.error("Internal Server Error", error);
    req.flash('error', error.message);
    res.redirect('/admin/reset-password');
  }
});

module.exports = router;