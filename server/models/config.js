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
        default: 'Project Walnut',
        min: [3, 'Site name must be at least 3 characters!'],
        max: [10, 'Site name is too long!'],
        trim: true
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
        required: true,
        min: [1, 'At least show one item per page, stupid!'],
        max: [10, 'No more than 100 items per page, silly!']
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
    },
    homeWelcomeText:{
        type: String,
        min: 5,
        max: 50
    },
    homeWelcomeSubText:{
        type: String,
        min: 5,
        max: 20
    },
    homepageWelcomeImage:{
        type: String
    },
    copyrightText:{
        type: String,
        default: 'Project Walnut. All rights reserved.'
    }
});

module.exports = mongoose.model('configSchema', configSchema);