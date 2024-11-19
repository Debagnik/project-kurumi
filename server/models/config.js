const mongoose = require('mongoose');

const schema = mongoose.Schema;
const configSchema = new schema({
    isRegistrationEnabled:{
        type: Boolean,
        default: false,
        required: true
    },
    siteName:{
        type: String,
        required: true,
        default: 'Project Walnut'
    },
    siteMetaDataKeywords:{
        type: String,
        required: true,
        default: 'Project Walnut, Blog, Node.js, Express.js, MongoDB'
    },
    siteMetaDataAuthor:{
        type: String,
        required: true,
        default: 'Debagnik Kar'
    },
    siteMetaDataDescription:{
        type: String,
        required: true,
        default: 'A simple blogging site created with Node, express and MongoDB'
    },
    siteAdminEmail:{
        type: String,
    },
    siteDefaultThumbnailUri:{
        type: String,
        default: 'https://via.placeholder.com/1440x720',
        required: true
    },
    defaultPaginationLimit:{
        type: Number,
        default: 2,
        required: true
    },
    lastModifiedDate:{
        type: Date,
        default: Date.now,
        required: true
    },
    lastModifiedBy:{
        type: String,
        required: true
    },
    googleAnalyticsScript:{
        type: String
    },
    inspectletScript:{
        type: String
    }
});

module.exports = mongoose.model('configSchema', configSchema);