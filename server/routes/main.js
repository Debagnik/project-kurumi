const express = require('express');
const router = express.Router();

//Routes
router.get('', (req, res) => {
    const locals = {
        title: "Blogging site",
        description: "A blogging site created with Node, express and MongoDB"
    }
    res.render('index',{locals});
});

router.get('/about', (req, res) => {
    const locals = {
        title: "About Us Section",
        description: "A blogging site created with Node, express and MongoDB"
    }
    res.render('about', {locals});
});

router.get('/contact', (req, res) => {
    const locals = {
        title: "Contacts us",
        description: "A blogging site created with Node, express and MongoDB"
    }
    res.render('contact', {locals});
});

module.exports = router;