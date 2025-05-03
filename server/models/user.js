const mongoose = require('mongoose');

const schema = mongoose.Schema;
const userSchema = new schema({
    username: {
        type: String,
        required: true,
        unique: true,
        minlength: [3, 'Username must be at least 3 characters!'],
        match: [/^[a-zA-Z0-9\-\_\.\+\@]+$/, 'Username can only contain letters, numbers, hyphens, underscores, dots, plus signs, and at-symbols!']
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
    },
    isPasswordReset: {
        type: Boolean,
        default: false,
        required: true
    },
    adminTempPassword: {
        type: String,
        required: false
    }
});

userSchema.index({
    username: 'text',
    name: 'text'
});
userSchema.pre('save', function(next) {
    if (this.isModified() && !this.isNew) {
        this.modifiedAt = Date.now();
    }
    next();
});

module.exports = mongoose.model('user', userSchema);