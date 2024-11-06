require('dotenv').config();

const express = require('express');
const expressLayout = require('express-ejs-layouts');
const connectDB = require('./server/config/db');

const app = express();
const PORT = process.env.PORT || 5000;

//connect Database
connectDB();

app.use(express.static('./public'));


//templating Engine
app.use(expressLayout);
app.set('layout', './layouts/main');
app.set('view engine', 'ejs');

app.use('/', require('./server/routes/main.js'))

app.listen(PORT , () => {
    console.log(`App is listening to PORT ${PORT}`);
});