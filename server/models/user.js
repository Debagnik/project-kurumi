const mongoose = require('mongoose');

const schema = mongoose.Schema;
const userSchema = new schema({
    username: {
        type: String,
        require: true,
        unique: true
    },
    password: {
        type: String,
        require: true
    },
    name:{
        type: String,
        require: true
    }
});

userSchema.index({
    username: 'text',
    name: 'text'
  });

module.exports = mongoose.model('user', userSchema);