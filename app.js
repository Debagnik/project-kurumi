require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const expressLayout = require('express-ejs-layouts');
const methodOverride = require('method-override');
const connectDB = require('./server/config/db');
const cookieParser = require('cookie-parser');
const mongoStore = require('connect-mongo');
const session = require('express-session');


const app = express();
// Add security headers.
app.use(helmet());
app.use(helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://www.googletagmanager.com", "https://cdn.inspectlet.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  }));

const PORT = process.env.PORT || 5000;

//connect Database
connectDB();

app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static('./public'));
app.use(cookieParser());
app.use(methodOverride('_method'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    store: mongoStore.create({
        mongoUrl: process.env.MONGO_DB_URI,
        ttl: 60 * 60,
        autoRemove: 'native',
        touchAfter: 24 * 60 * 60
    }),
    cookie:{
        maxAge: 3600000,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict'
    }
}));

//templating Engine
app.use(expressLayout);
app.set('layout', './layouts/main');
app.set('view engine', 'ejs');

app.use('/', require('./server/routes/main.js'));
app.use('/', require('./server/routes/admin.js'));

// 404 Not Found Middleware
app.use((req, res, next) => {
    const locals = {
        title: '404 - Page Not Found',
        description: '404 Not Found',
        config: res.locals.siteConfig
    }
    res.status(404).render('404', {locals});
});

// Middleware to protect routes, CSRF Error Handler
app.use(function (err, req, res, next) {
    if (err.code !== 'EBADCSRFTOKEN'){
        return next(err);
    }

    console.error('CSRF attempt detected:', {
        path: req.path,
        ip: req.ip,
        timestamp: new Date().toISOString()
    });
  
    // handle CSRF token errors here
    res.status(403).json({error: 'Invalid CSRF token', message: 'Your session has expired or the form submission was rejected for security reasons. Please refresh the page and try again. Contact webmaster if this issue persists'
    });
    res.send('Form tampered with');
});

app.listen(PORT , () => {
    console.log(`App is listening to PORT ${PORT}`);
});