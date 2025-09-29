require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const expressLayout = require('express-ejs-layouts');
const methodOverride = require('method-override');
const connectDB = require('./server/config/db');
const cookieParser = require('cookie-parser');
const mongoStore = require('connect-mongo');
const session = require('express-session');
const flash = require('connect-flash');

const app = express();
// Add security headers.
app.use(helmet());
app.use(
    helmet.contentSecurityPolicy({
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://www.googletagmanager.com",
          "https://*.inspectlet.com",
          "https://challenges.cloudflare.com",
          "https://*.clarity.ms",
          "https://fonts.googleapis.com",
          "https://*.cloudflareinsights.com"
        ],
        scriptSrcElem: [
          "'self'",
          "'unsafe-inline'",
          "https://www.googletagmanager.com",
          "https://*.inspectlet.com",
          "https://challenges.cloudflare.com",
          "https://fonts.googleapis.com",
          "https://*.cloudflareinsights.com",
          "https://*.clarity.ms"
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com"
        ],
        styleSrcElem: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com"
        ],
        fontSrc: [
          "'self'",
          "https://fonts.gstatic.com"
        ],
        connectSrc: [
          "'self'",
          "https://www.google-analytics.com",
          "https://*.clarity.ms",
          "https://*.inspectlet.com",
          "https://*.cloudflareinsights.com"
        ],
        imgSrc: ["'self'", "data:", "https:"],
        frameSrc: [
          "'self'",
          "https://challenges.cloudflare.com"
        ],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'self'"],
        scriptSrcAttr: ["'none'"],
        upgradeInsecureRequests: []
      }
    })
  );

const PORT = process.env.PORT || 5000;

//connect Database
connectDB();

app.use(express.urlencoded({extended: true}));
app.use(express.json());
app.use(express.static('./public'));
app.use(cookieParser());
app.use(methodOverride('_method'));
app.set('trust proxy', 1);
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: process.env.NODE_ENV !== 'production',
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

// Connect flash for flash messages
app.use(flash());

// Flash messages middleware
app.use((req, res, next) => {
  res.locals.flash = {
    success_msg: req.flash('success'),
    error_msg: req.flash('error'),
    info_msg: req.flash('info')
  };
  next();
});

//templating Engine
app.use(expressLayout);
app.set('layout', './layouts/main');
app.set('view engine', 'ejs');

app.use('/', require('./server/routes/main.js'));
app.use('/', require('./server/routes/admin.js'));

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

// 404 Not Found Middleware
app.use((req, res, next) => {
    const locals = {
        title: '404 - Page Not Found',
        description: '404 Not Found',
        config: res.locals.siteConfig
    }
    res.status(404).render('404', {locals, csrfToken: req.csrfToken()});
});


// Start the server
app.listen(PORT , () => {
    console.log(`App is listening to PORT ${PORT}`);
});