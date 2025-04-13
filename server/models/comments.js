const mongoose = require('mongoose');

const schema = mongoose.Schema;
const CommentSchema = new schema({
    commenterName: {
        type: String,
        required: true,
        minlength: [3, 'Commenter name must be at least 3 characters!'],
        maxlength: [50, 'Commenter name is too long!'],
        trim: true,
        set: value => value.replace(/<\/?[^>]+(>|$)/g, '')

    },
    commentBody: {
        type: String,
        required: true,
        minlength: [1, 'Comment must be at least 1 character!'],
        maxlength: [500, 'Comment is too long!'],
        trim: true,
        set: value => value.replace(/<\/?[^>]+(>|$)/g, '')
    },
    commentTimestamp: {
        type: Date,
        default: Date.now,
        required: true
    },
    postId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Post',
        required: true,
        index: true
    }
});
CommentSchema.index({
    commenterName: 'text',
    commentBody: 'text',
    commentTimestamp: -1
});

module.exports = mongoose.model('comment', CommentSchema);
