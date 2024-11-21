const mongoose = require('mongoose');

const schema = mongoose.Schema;
const userSchema = new schema({
    username: {
        type: String,
        required: true,
        unique: true,
        minlength: [3, 'Username must be at least 3 characters!'],
        match: [/^[a-zA-Z0-9]+$/, 'Username can only contain letters and numbers!']
    },
    password: {
        type: String,
        required: true,
        minlength: [8, 'Password too weak!']
    },
    name:{
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    /**
     * User privilege level
     * 1 = Webmaster
     * 2 = Admin
     * 3 = Regular User (default)
     * 4 = Unlogged User - Not required now
     */
    privilege:{
        type: Number,
        default: 3,
        required: true
    },
    modifiedAt:{
        type: Date,
        default: Date.now
    }
});

userSchema.index({
    username: 'text',
    name: 'text'
  });

module.exports = mongoose.model('user', userSchema);