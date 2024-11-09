const mongoose = require('mongoose');
const connectDB = async() => {
    try{
        mongoose.set('strictQuery', false);
        const connection = await mongoose.connect(process.env.MONGO_DB_URI);
        console.log(`DB Connected: ${connection.connection.host}`);
    } catch(error){
        console.log(error);
    }
}

module.exports = connectDB;