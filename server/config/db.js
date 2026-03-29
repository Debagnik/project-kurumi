const mongoose = require('mongoose');
const logger = require('../../utils/logger');
const MAX_RETRY = 3;
const RETRY_DELAY = 5000;


const connectDB = async(retryCount = 0) => {
    try{
        mongoose.set('strictQuery', false);
        const connection = await mongoose.connect(process.env.MONGO_DB_URI);
        logger.info(`DB Connected: ${connection.connection.host}`);
    } catch(error){
        logger.error(`Database connection attempt ${retryCount + 1} failed:`, error.message);
        if (retryCount < MAX_RETRY) {
            const http = require('node:http');
            http.get({'host': 'api.ipify.org', 'port': 80, 'path': '/'}, function(resp) {
                resp.on('data', function(ip) {
                  logger.info("My public IP address is: " + ip);
                });
              });
            logger.info(`Retrying in ${RETRY_DELAY/1000} seconds...`);
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            return connectDB(retryCount + 1);
        }
        logger.error('Max retry attempts reached. Exiting...');
        process.exit(1);
    }
}

module.exports = connectDB;