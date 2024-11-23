const express = require('express');
const router = express.Router();
const post = require('../models/posts');
const siteConfig = require('../models/config');

/**
 * Site config Middleware
 */

const fetchSiteConfig = async (req, res, next) => {
    try {
        const config = await siteConfig.findOne();
        if (!config) {
            console.warn('Site config is not available');
            res.locals.siteConfig = {};
        } else {
            res.locals.siteConfig = config;
        }
        next();
    } catch (error) {
        console.error("Site Config Fetch error", error.message);
        res.locals.siteConfig = {};
        next();
    }
}

router.use(fetchSiteConfig);

//Routes
/**
 * GET /
 * HOME
 */
router.get('', async (req, res) => {

    try {
        const locals = {
            title: res.locals.siteConfig.siteName || "Project Walnut",
            description: res.locals.siteConfig.siteMetaDataDescription || "A blogging site created with Node, express and MongoDB"
        }

        let perPage = res.locals.siteConfig.defaultPaginationLimit || 1;
        let page = req.query.page || 1;

        const data = await post.aggregate([{ $sort: { createdAt: -1 } }]).skip(perPage * page - perPage)
            .limit(perPage).exec();

        const count = await post.countDocuments({});
        const nextPage = parseInt(page) + 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);


        res.render('index', { 
            locals,
            config: res.locals.siteConfig,
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
        title: "About Us Section",
        description: "A blogging site created with Node, express and MongoDB"
    }
    res.render('about', { 
        locals,
        config: res.locals.siteConfig,
     });
});

/**
 * GET /contact
 * Contact
 */
router.get('/contact', (req, res) => {
    const locals = {
        title: "Contacts us",
        description: "A blogging site created with Node, express and MongoDB"
    }
    res.render('contact', { 
        locals,
        config: res.locals.siteConfig
     });
});

/**
 * GET /
 * Posts :id
 */
router.get('/post/:id', async (req, res) => {
    try {
        let slug = req.params.id;
        const data = await post.findById({ _id: slug });
        if (!data) {
            throw new Error('404 - No such post found');
        }
        const locals = {
            title: data.title,
            description: data.desc,
            keywords: data.tags
        }

        res.render('posts', { 
            locals,
            data,
            config: res.locals.siteConfig
        });
    } catch (error) {
        console.error('Post Fetch error', error);
        res.status(404).render('404', {
            locals: {
                title: "404 - Page Not Found",
                description: "The page you're looking for doesn't exist."
            },
            config: res.locals.siteConfig
        });
    }
});

/**
 * POST /
 * Search: Search term
 */
router.post('/search', async (req, res) => {
    try {

        let searchLimit = 20;
        let searchTerm = req.body.searchTerm;
        if (!searchTerm || typeof searchTerm !== 'string') {
            return res.status(400).json({ error: 'Invalid search term' });
        }
        if (searchTerm.trim().length == 0) {
            return res.status(400).json({ error: 'Search term cannot be empty' });
        }
        const searchNoSpecialChar = searchTerm.replace(/[^a-zA-Z0-9 ]/g, "");
        console.log(new Date(), " - Simple Search - ", searchTerm, " - regex search: ", searchNoSpecialChar);

        const locals = {
            title: "Search - " + searchTerm,
            description: "Simple Search Page"
        }

        const data = await post.find(
            { $text: { $search: searchNoSpecialChar } },
            { score: { $meta: 'textScore' } }
        )
            .sort({ score: { $meta: 'textScore' } })
            .limit(searchLimit);

        res.render('search', { data, locals, searchTerm: searchTerm, config: res.locals.siteConfig });
    } catch (error) {
        console.error('Search error:', error);
        res.status(500).render('404', {
            locals: {
                title: 'Error'
            },
            error: 'Unable to perform search at this time',
            config: res.locals.siteConfig
        });
    }
})

module.exports = router;
