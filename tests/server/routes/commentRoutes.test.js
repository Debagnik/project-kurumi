const request = require('supertest');
const express = require('express');
const logger = require('../../../utils/logger');

// Mock environment variables
process.env.JWT_SECRET = 'test-secret-key';
process.env.NODE_ENV = 'test';
process.env.MAX_COMMENTS_LIMIT = '10';

// Mock modules
jest.mock('../../../utils/openRouterIntegration', () => jest.fn());
jest.mock('../../../utils/cloudflareTurnstileServerVerify.js', () => jest.fn());
jest.mock('../../../utils/validations.js', () => ({
    parseTags: jest.fn(),
    isValidURI: jest.fn()
}));
jest.mock('jsonwebtoken', () => ({
    verify: jest.fn(),
    sign: jest.fn()
}));
jest.mock('sanitize-html', () => jest.fn(input => input));
jest.mock('mongoose', () => ({
    Types: {
        ObjectId: {
            isValid: jest.fn()
        }
    },
    connection: { readyState: 1 }
}));

// Mock data models
jest.mock('../../../server/models/posts', () => ({
    findById: jest.fn(),
    findOne: jest.fn(),
    find: jest.fn(),
    aggregate: jest.fn(),
    countDocuments: jest.fn()
}));
jest.mock('../../../server/models/user', () => ({
    findById: jest.fn(),
    findOne: jest.fn()
}));
jest.mock('../../../server/models/comments', () => ({
    findById: jest.fn(),
    find: jest.fn(),
    create: jest.fn(),
    prototype: { save: jest.fn(), deleteOne: jest.fn() }
}));
jest.mock('../../../server/models/config', () => ({
    findOne: jest.fn(),
    findOneAndUpdate: jest.fn()
}));

const testSiteConfig = {
    siteName: 'Test Blog',
    siteMetaDataDescription: 'Test Description',
    isRegistrationEnabled: true,
    defaultPaginationLimit: 5,
    searchLimit: 10,
    isCommentsEnabled: true,
    isCaptchaEnabled: false,
    cloudflareSiteKey: 'test-site-key',
    cloudflareServerKey: 'test-server-key'
};

function resetSiteConfig() {
    Object.assign(testSiteConfig, {
        siteName: 'Test Blog',
        siteMetaDataDescription: 'Test Description',
        isRegistrationEnabled: true,
        defaultPaginationLimit: 5,
        searchLimit: 10,
        isCommentsEnabled: true,
        isCaptchaEnabled: false,
        cloudflareSiteKey: 'test-site-key',
        cloudflareServerKey: 'test-server-key'
    });
}

// Mock utilities
jest.mock('../../../utils/fetchSiteConfigurations.js', () => ({
    fetchSiteConfigCached: (req, res, next) => { res.locals.siteConfig = testSiteConfig; next(); },
    invalidateCache: jest.fn(),
    getCacheStatus: jest.fn(() => 'available')
}));
jest.mock('../../../utils/postCache.js', () => ({
    getPostFromCache: jest.fn(),
    setPostToCache: jest.fn(),
    getCacheSize: jest.fn(() => ({ maxCacheSize: 100, cacheSize: 10 })),
    invalidate: jest.fn()
}));
jest.mock('../../../utils/rateLimiter', () => ({
    genericOpenRateLimiter: (req, res, next) => next(),
    genericAdminRateLimiter: (req, res, next) => next(),
    genericGetRequestRateLimiter: (req, res, next) => next(),
    commentsRateLimiter: (req, res, next) => next()
}));
jest.mock('csurf', () => () => (req, res, next) => { req.csrfToken = () => 'test-csrf-token'; next(); });

function createApp() {
    const app = express();
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.use(require('cookie-parser')());
    app.use((req, res, next) => {
        req.flash = jest.fn();
        req.ip = '127.0.0.1';
        next();
    });
    app.use((req, res, next) => {
        res.render = jest.fn((tpl, data) => {
            res.status(200).json({ template: tpl, data });
        });
        // Guard against double-redirect crashes in tests
        const originalRedirect = res.redirect;
        res.redirect = function () {
            if (res.headersSent) return;
            return originalRedirect.apply(this, arguments);
        };
        next();
    });
    const mainRouter = require('../../../server/routes/main.js');
    app.use('/', mainRouter);
    return app;
}

describe('Additional comment and utility route tests', () => {
    let app;
    let mockPost, mockUser, mockComment, mockJwt, mockSanitizeHtml, mockMongoose, mockPostCache, mockCaptcha, mockUtils;

    afterAll(() => {
        jest.restoreAllMocks();
    });

    beforeAll(() => {
        app = createApp();
        mockPost = require('../../../server/models/posts');
        mockUser = require('../../../server/models/user');
        mockComment = require('../../../server/models/comments');
        mockJwt = require('jsonwebtoken');
        mockSanitizeHtml = require('sanitize-html');
        mockMongoose = require('mongoose');
        mockPostCache = require('../../../utils/postCache');
        mockCaptcha = require('../../../utils/cloudflareTurnstileServerVerify.js');
        mockUtils = require('../../../utils/validations.js');
    });

    beforeEach(() => {
        jest.clearAllMocks();
        resetSiteConfig();
        mockPost.findById.mockResolvedValue({ _id: '1', isApproved: true, uniqueId: 'test-unique-id' });
        mockPost.findOne.mockResolvedValue({ _id: '1', author: 'testuser', uniqueId: 'test-unique-id', isApproved: true });
        mockPost.aggregate.mockReturnValue({
            skip: jest.fn().mockReturnThis(),
            limit: jest.fn().mockReturnThis(),
            exec: jest.fn().mockResolvedValue([])
        });
        mockPost.countDocuments.mockResolvedValue(0);
        mockUser.findOne.mockResolvedValue(null);
        mockUser.findById.mockResolvedValue(null);
        mockComment.findById.mockResolvedValue({
            postId: '1',
            deleteOne: jest.fn().mockResolvedValue(true)
        });
        mockComment.find.mockReturnValue({
            sort: jest.fn().mockReturnThis(),
            limit: jest.fn().mockReturnThis(),
            exec: jest.fn().mockResolvedValue([])
        });
        mockJwt.verify.mockReturnValue({ userId: 'user123' });
        mockMongoose.Types.ObjectId.isValid.mockReturnValue(true);
        mockPostCache.getPostFromCache.mockReturnValue(null);
        mockCaptcha.mockResolvedValue(true);
        mockSanitizeHtml.mockImplementation(i => i);
        mockUtils.parseTags.mockReturnValue([]);
        mockUtils.isValidURI.mockReturnValue(true);
    });

    test('POST comment with mismatched IDs should 404', async () => {
        const response = await request(app)
            .post('/posts/507f1f77bcf86cd799439011/post-comments')
            .send({ postId: '507f1f77bcf86cd799439012', commenterName: 'Tester', commentBody: 'Nice' });
        expect(response.status).toBe(302);
        expect(response.headers.location).toBe('/404');
    });

    test('POST comment with invalid ObjectId should 404', async () => {
        mockMongoose.Types.ObjectId.isValid.mockReturnValue(false);
        const response = await request(app)
            .post('/posts/invalid-id/post-comments')
            .send({ postId: 'invalid-id', commenterName: 'Tester', commentBody: 'Nice' });
        expect(response.status).toBe(302);
        expect(response.headers.location).toBe('/404');
    });

    test('POST comment when CAPTCHA fails should 403', async () => {
        testSiteConfig.isCaptchaEnabled = true;
        mockCaptcha.mockResolvedValue(false);
        const response = await request(app)
            .post('/posts/507f1f77bcf86cd799439011/post-comments')
            .send({ postId: '507f1f77bcf86cd799439011', commenterName: 'Tester', commentBody: 'Nice' });
        // CAPTCHA failure triggers res.status(403).redirect() which sends a 302
        expect(response.status).toBe(302);
    });

    test('DELETE comment authorized admin should succeed', async () => {
        // WEBMASTER = 1 per constants.js
        mockJwt.verify.mockReturnValue({ userId: 'admin123' });
        mockUser.findById.mockResolvedValue({ _id: 'admin123', username: 'admin', privilege: 1 });
        // Mock post lookup for redirect after delete
        mockPost.findById.mockResolvedValue({ _id: '1', uniqueId: 'test-unique-id' });
        const response = await request(app)
            .post('/posts/delete-comment/comment-id')
            .set('Cookie', ['token=valid-token']);
        // Route does res.status(200).redirect(url) which sends a 302
        expect(response.status).toBe(302);
        expect(response.headers.location).toBe('/posts/test-unique-id');
    });

    test('DELETE comment unauthorized user should 403 and redirect to /admin', async () => {
        mockJwt.verify.mockReturnValue({ userId: 'user123' });
        // EDITOR = 3, not a mod or admin
        mockUser.findById.mockResolvedValue({ _id: 'user123', privilege: 3 });
        const response = await request(app)
            .post('/posts/delete-comment/comment-id')
            .set('Cookie', ['token=valid-token']);
        expect(response.status).toBe(302);
        expect(response.headers.location).toBe('/admin');
    });

    test('GET /advanced-search returns 200 and template', async () => {
        const response = await request(app).get('/advanced-search');
        expect(response.status).toBe(200);
        expect(response.body.template).toBe('advanced-search');
    });

    test('GET existing user profile returns 200', async () => {
        mockUser.findOne.mockResolvedValue({
            username: 'john',
            name: 'John Doe',
            htmlDesc: '<p>Hello</p>',
            portfolioLink: 'https://example.com',
            modifiedAt: new Date()
        });
        const response = await request(app).get('/users/john');
        expect(response.status).toBe(200);
        expect(response.body.template).toBe('users');
    });

    test('GET non-existing user redirects to home', async () => {
        mockUser.findOne.mockResolvedValue(null);
        const response = await request(app).get('/users/ghost');
        expect(response.status).toBe(302);
        expect(response.headers.location).toBe('/');
    });

    test('GET /healthz returns JSON status ok', async () => {
        const response = await request(app).get('/healthz');
        expect(response.status).toBe(200);
        expect(response.body.status).toBe('ok');
    });
});
