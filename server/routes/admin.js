const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const router = express.Router();
const post = require('../models/posts');
const user = require('../models/user')

const jwtSecretKey = process.env.JWT_SECRET;
const adminLayout = '../views/layouts/admin';

//Routes
/**
 * GET /
 * ADMIN - Login
 */

router.get('/admin', async (req, res) => {
  try {

    const locals = {
      title: "Admin Panel",
      description: "Admin Panel"
    }
    res.render('admin/index', { locals, layout: adminLayout, isRegistrationEnabled: process.env.ENABLE_REGISTRATION });
  } catch (error) {
    console.error("Admin Page error", error.message);
  }

});

/**
 * POST /
 * ADMIN - Register
 */
router.post('/register', async (req, res) => {
  try {
    const { username, password, name } = req.body;

    if (process.env.ENABLE_REGISTRATION === 'true') {
      if (!(username === '' || password === '' || name === '')) {
        const hashedPassword = await bcrypt.hash(password, 10);
        try {
          const newUser = await user.create({ username, password: hashedPassword, name });
          console.log('User created', newUser, 201);
        } catch (error) {
          if (error.code === 11000) {
            console.error(409, 'Username already exists');
            res.status(409).json({ message: 'User Exists' });
          }
          else {
            console.error(500, 'Internal Server Error');
            res.status(500).json({ message: 'Internal Server Error' });
          }
        }
      } else {
        res.status(401).json({ message: 'name, username or password cannot be empty' });
      }
    } else {
      res.status(404).json('Not accepting registration');
      console.warn('registration not enabled');
    }
    res.redirect('/admin/registration');
  } catch (error) {
    console.error('error in post', error);
  }
});

/**
 * POST
 * Admin - Check Login
 */
router.post('/admin', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!(username === '' || password === '')) {
      const currentUser = await user.findOne({ username });
      if (!currentUser) {
        console.error(401, 'invalid credentials for user: ', username);
        return res.status(401).json({ message: 'invalid credentials' });
      }
      const isPasswordValid = bcrypt.compare(password, currentUser.password);
      if (!isPasswordValid) {
        console.error(401, 'invalid credentials for user: ', username);
        return res.status(401).json({ message: 'invalid credentials' });
      }
      const token = jwt.sign({ userId: currentUser._id }, jwtSecretKey);
      res.cookie('token', token, { httpOnly: true });
      res.redirect('/dashboard');
    } else {
      console.error(401, "username or password is empty");
      return res.status(401).json({ message: 'atleast enter some values bruh' });
    }
  } catch (error) {
    console.error(error);
  }
});

/**
 * GET
 * Admin - Registration success
 */

router.get('/admin/registration', async (req, res) => {
  const locals = {
    title: 'Registration successful',
    description: 'Registration successful'
  };
  res.render('admin/registration', { locals, layout: adminLayout });
});

router.get('/dashboard', async (req, res) => {
  res.render('admin/dashboard');
});

module.exports = router;