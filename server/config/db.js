const mongoose = require('mongoose');
const logger = require('../../utils/logger');
const MAX_RETRY = 3;
const RETRY_DELAY = 500;
const https = require('node:https');


const connectDB = async (req, res, next) => {
    // If the database is already connected, continue to the next middleware
    if (mongoose.connection.readyState === 1) {
        return next();
    }

    const connectWithRetry = async (retryCount = 0) => {
        try {
            mongoose.set('strictQuery', false);
            const connection = await mongoose.connect(process.env.MONGO_DB_URI);
            logger.info(`DB Connected: ${connection.connection.host}`);
            next(); // Proceed to next middleware on successful connection
        } catch(error) {
            logger.error(`Database connection attempt ${retryCount + 1} failed:`, error.message);
            if (retryCount < MAX_RETRY) {
                try {
                    https.get('https://ipinfo.io/ip', function(resp) {
                        let ipAddress = '';
                        resp.on('data', function(chunk) {
                            ipAddress += chunk;
                        });
                        resp.on('end', function() {
                            logger.info("My public IP address is: " + ipAddress);
                        });
                    }).on('error', function(error) {
                        logger.error({message: "Failed to get IP address", error: error.message});
                    });
                } catch (error) {
                    logger.error("Error during IP fetch setup:", error.message);
                }
                logger.info(`Retrying in ${RETRY_DELAY/1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
                return connectWithRetry(retryCount + 1);
            }
            logger.error('Max retry attempts reached. Rendering error page...');
            const locals = {
                config: {}
            };
            return res.status(500).render('error', { locals });
        }
    };

    await connectWithRetry().catch(next);
}

module.exports = connectDB;