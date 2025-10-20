const mongoose = require('mongoose');
const MAX_RETRY = 3;
const RETRY_DELAY = 5000;


const connectDB = async(retryCount = 0) => {
    try{
        mongoose.set('strictQuery', false);
        const connection = await mongoose.connect(process.env.MONGO_DB_URI);
        console.log(`DB Connected: ${connection.connection.host}`);
    } catch(error){
        console.log(`Database connection attempt ${retryCount + 1} failed:`, error.message);
        if (retryCount < MAX_RETRY) {
            var http = require('http');
            http.get({'host': 'api.ipify.org', 'port': 80, 'path': '/'}, function(resp) {
                resp.on('data', function(ip) {
                  console.log("My public IP address is: " + ip);
                });
              });
            console.log(`Retrying in ${RETRY_DELAY/1000} seconds...`);
            await new Promise(resolve => setTimeout(resolve, RETRY_DELAY));
            return connectDB(retryCount + 1);
        }
        console.error('Max retry attempts reached. Exiting...');
        process.exit(1);
    }
}

module.exports = connectDB;