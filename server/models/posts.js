const mongoose = require('mongoose');

const schema = mongoose.Schema;
const postSchema = new schema({
    title: {
        type: String,
        required: true
    },
    markdownbody: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    modifiedAt: {
        type: Date,
        default: Date.now
    },
    desc: {
        type: String
    },
    author: {
        type: String,
        required: true
    },
    tags: {
        type: [String],
        required: true
    },
    thumbnailImageURI: {
        type: String,
        required: true
    },
    lastUpdateAuthor: {
        type: String,
        required: true
    },
    body: {
        type: String,
        required: true
    },
    isApproved: {
        type: Boolean,
        default: false,
        required: true
    },
    uniqueId: {
        type: String,
        required: true,
        unique: true
    }

});

postSchema.index({
    title: 'text',
    body: 'text',
    tags: 'text',
    author: 'text',
}, {
    name: 'TextSearchIndex'
});

postSchema.index({
    isApproved: 1,
    createdAt: -1
}, {
    name: 'ApprovedDateIndex'
});

postSchema.index({
    uniqueId: 1
}, {
    name: 'UniqueIdIndex',
    unique: true
});


postSchema.index({
    tags: 1
}, {
    name: 'TagsMultikeyIndex'
});

module.exports = mongoose.model('Posts', postSchema);