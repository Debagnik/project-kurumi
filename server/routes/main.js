const express = require('express');
const router = express.Router();
const post = require('../models/posts');


//Routes
/**
 * GET /
 * HOME
 */
router.get('', async (req, res) => {

    try {
        const locals = {
            title: "Blogging site",
            description: "A blogging site created with Node, express and MongoDB"
        }

        let perPage = 2;
        let page = req.query.page || 1;

        const data = await post.aggregate([{ $sort: { createdAt: -1 } }]).skip(perPage * page - perPage)
            .limit(perPage).exec();

        const count = await post.countDocuments({});
        const nextPage = parseInt(page) + 1;
        const hasNextPage = nextPage <= Math.ceil(count / perPage);


        res.render('index', { locals, data, current: page, nextPage: hasNextPage ? nextPage : null });
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
    res.render('about', { locals });
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
    res.render('contact', { locals });
});

/**
 * GET /
 * Posts :id
 */
router.get('/post/:id', async (req, res) => {
    try {
        let slug = req.params.id;
        const data = await post.findById({ _id: slug });
        if(!data) {
            throw new Error('404 - No such post found');
        }
        const locals = {
            title: data.title,
            description: data.desc,
            keywords: data.tags
        }

        res.render('posts', { locals, data });
    } catch (error) {
        console.error('Post Fetch error', error);
        res.status(500).render('404', {
            locals: {
                title: "404 - Page Not Found",
                description: "The page you're looking for doesn't exist."
            }
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
        if(!searchTerm || typeof searchTerm !== 'string'){
            return res.status(400).json({ error: 'Invalid search term' });
        }
        if(searchTerm.trim().length == 0){
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

        res.render('search', {data, locals, searchTerm: searchTerm});
    } catch (error) { 
        console.error('Search error:', error );
        res.status(500).render('error', {
            locals: {
                title: 'Error'
            },
            error: 'Unable to perform search at this time'
        });
    }
})

module.exports = router;