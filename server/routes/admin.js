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
    res.render('admin/index', { locals, layout: adminLayout, isRegistrationEnabled: process.env.ENABLE_REGISTRATION, errors: [], errors_login: [] });
  } catch (error) {
    console.error("Admin Page error", error.message);
    res.status(500).send('Internal Server Error');
  }

});

/**
 * POST /
 * ADMIN - Register
 */
router.post('/register', async (req, res) => {
  try {
    const { username, password, name } = req.body;

    //check for empty field
    if (!name || !username || !password) {
      console.log(401, 'empty mandatory fields');
      return res.render('admin/index', {
        errors: [{ msg: 'Name, Username or Passwords are empty' }],
        isRegistrationEnabled: process.env.ENABLE_REGISTRATION
      });
    }

    // checking for existing user
    const existingUser = await user.findOne({ username })
    if (existingUser) {
      console.error(409, 'Username already exists');
      return res.render('admin/index', {
        errors: [{ msg: 'Username already exists!' }],
        isRegistrationEnabled: process.env.ENABLE_REGISTRATION
      });
    }


    //registration logic
    if (process.env.ENABLE_REGISTRATION === 'true') {
      const hashedPassword = await bcrypt.hash(password, 10);
      try {
        const newUser = await user.create({ username, password: hashedPassword, name });
        console.log('User created', newUser, 201);
        res.redirect('/admin/registration');
      } catch (error) {
        if (error.code === 11000) {
          console.error(409, 'Username already exists 2');
        }
        else {
          console.error(500, 'Internal Server Error');
          return res.render('admin/index', {
            errors: [{
              msg: 'We are facing some difficulty. Please hang back while we resolve this issue.'
            }],
            isRegistrationEnabled: process.env.ENABLE_REGISTRATION
          });
        }
      }
    } else {
      return res.render('admin/index', {
        errors: [{
          msg: 'Registration not enabled, Contact with Site admin or God-father'
        }],
        isRegistrationEnabled: process.env.ENABLE_REGISTRATION
      });
    }
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

    //checks if the username or passwords are not empty
    if (!username || !password) {
      return res.render('admin/index', {
        errors_login: [{
          msg: 'Username and Passwords are mandatory'
        }],
        isRegistrationEnabled: process.env.ENABLE_REGISTRATION,
        errors:[]
      });
    }

    //checks if the user exists
    const currentUser = await user.findOne({ username });
    if (!currentUser) {
      console.error(401, 'invalid credentials for user: ', username);
      return res.render('admin/index', {
        errors_login: [{ msg: 'Invalid login credentials!' }],
        isRegistrationEnabled: process.env.ENABLE_REGISTRATION,
        errors:[]
      });
    }

    //password validity check
    const isPasswordValid = await bcrypt.compare(password, currentUser.password);
    if (!isPasswordValid) {
      console.error(401, 'invalid credentials for user: ', username);
      return res.render('admin/index', {
        errors_login: [{ msg: 'Invalid login credentials!' }],
        isRegistrationEnabled: process.env.ENABLE_REGISTRATION,
        errors:[]
      });
    }

    //adds session
    const token = jwt.sign({ userId: currentUser._id }, jwtSecretKey);
    res.cookie('token', token, { httpOnly: true });
    res.redirect('/dashboard');
  } catch (error) {
    //for any other errors
    console.error(error);
    return res.render('admin/index', {
      errors_login: [{ msg: 'We are facing some difficulty. Please hang back while we resolve this issue.' }],
      isRegistrationEnabled: process.env.ENABLE_REGISTRATION,
      errors:[]
    });
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