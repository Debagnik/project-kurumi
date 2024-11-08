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
        console.log(`DB Data fetched`);
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
    try{
        let slug = req.params.id;
        const data = await post.findById({_id: slug});
        const locals = {
            title: data.title,
            description: data.tags
        }
        
        res.render('posts', {locals, data});
    }catch(error){
        console.log(error);
    }
});

module.exports = router;