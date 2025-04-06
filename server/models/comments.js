const mongoose = require('mongoose');

const schema = mongoose.Schema;
schema = new mongoose.Schema({
    commentersName: {
        type: String,
        required: true,
        minlength: [3, 'Commenter name must be at least 3 characters!'],
        maxlength: [50, 'Commenter name is too long!'],
        trim: true
    },
    commentBody: {
        type: String,
        required: true,
        minlength: [1, 'Comment must be at least 1 characters!'],
        maxlength: [500, 'Comment is too long!'],
        trim: true
    },
    commentTimestamp: {
        type: Date,
        default: Date.now,
        required: true
    },
    postId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Post',
        required: true
    }
});
