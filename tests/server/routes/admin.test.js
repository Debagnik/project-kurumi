/**
 * Admin Route Tests for 90%+ Coverage
 * Focused on line coverage with proper mocking
 */

// Set up environment variables
process.env.JWT_SECRET = 'test-secret-key';
process.env.NODE_ENV = 'test';
process.env.MAX_DESCRIPTION_LENGTH = '1000';
process.env.MAX_TITLE_LENGTH = '50';
process.env.MAX_BODY_LENGTH = '100000';
process.env.MAX_NAME_LENGTH = '100';
process.env.DEFAULT_POST_THUMBNAIL_LINK = 'https://example.com/default.jpg';

// Mock all external dependencies
jest.mock('jsonwebtoken', () => ({
    verify: jest.fn(),
    sign: jest.fn()
}));

jest.mock('bcrypt', () => ({
    hash: jest.fn(),
    compare: jest.fn()
}));

jest.mock('sanitize-html', () => jest.fn((input) => input));
jest.mock('marked', () => ({
    parse: jest.fn((input) => `<p>${input}</p>`)
}));

jest.mock('mongoose', () => ({
    Types: {
        ObjectId: {
            isValid: jest.fn()
        }
    },
    connection: {
        readyState: 1
    }
}));

// Mock models
const mockPostSave = jest.fn();
const mockUserSave = jest.fn();
const mockConfigSave = jest.fn();

jest.mock('../../../server/models/posts', () => {
    const mockPost = jest.fn().mockImplementation((data) => ({
        ...data,
        _id: 'post123',
        save: mockPostSave
    }));
    mockPost.findOne = jest.fn();
    mockPost.find = jest.fn();
    mockPost.findById = jest.fn();
    mockPost.findByIdAndUpdate = jest.fn();
    mockPost.deleteOne = jest.fn();
    return mockPost;
});

jest.mock('../../../server/models/user', () => {
    const mockUser = jest.fn().mockImplementation((data) => ({
        ...data,
        _id: 'user123',
        save: mockUserSave
    }));
    mockUser.findById = jest.fn();
    mockUser.findOne = jest.fn();
    mockUser.find = jest.fn();
    mockUser.create = jest.fn();
    mockUser.deleteOne = jest.fn();
    return mockUser;
});

jest.mock('../../../server/models/comments', () => ({
    deleteMany: jest.fn()
}));

jest.mock('../../../server/models/config', () => {
    const mockSiteConfig = jest.fn().mockImplementation((data) => ({
        ...data,
        save: mockConfigSave
    }));
    mockSiteConfig.findOne = jest.fn();
    mockSiteConfig.findOneAndUpdate = jest.fn();
    return mockSiteConfig;
});

// Mock utilities
jest.mock('../../../utils/validations.js', () => ({
    parseTags: jest.fn((tags) => tags ? tags.split(',').map(tag => tag.trim()) : []),
    isValidURI: jest.fn((uri) => uri && uri.startsWith('http')),
    isWebMaster: jest.fn((user) => user && user.privilege === 3),
    isValidTrackingScript: jest.fn((script) => script || ''),
    createUniqueId: jest.fn((title) => title.toLowerCase().replace(/\s+/g, '-'))
}));

jest.mock('../../../utils/openRouterIntegration', () => ({
    summarizeMarkdownBody: jest.fn()
}));

jest.mock('../../../utils/fetchSiteConfigurations.js', () => ({
    fetchSiteConfigCached: (req, res, next) => {
        res.locals.siteConfig = {
            siteName: 'Test Blog',
            isRegistrationEnabled: true,
            defaultPaginationLimit: 5,
            searchLimit: 10,
            isCommentsEnabled: true,
            isCaptchaEnabled: false,
            siteDefaultThumbnailUri: 'https://example.com/default.jpg',
            homepageWelcomeImage: 'https://example.com/welcome.jpg'
        };
        next();
    },
    invalidateCache: jest.fn()
}));

jest.mock('../../../utils/postCache.js', () => ({
    invalidateCache: jest.fn()
}));

jest.mock('../../../utils/rateLimiter', () => ({
    genericAdminRateLimiter: (req, res, next) => next(),
    authRateLimiter: (req, res, next) => next(),
    genericGetRequestRateLimiter: (req, res, next) => next(),
    aiSummaryRateLimiter: (req, res, next) => next()
}));

jest.mock('csurf', () => () => (req, res, next) => {
    req.csrfToken = () => 'test-csrf-token';
    next();
});

jest.mock('../../../utils/constants', () => ({
    CONSTANTS: {
        USERNAME_REGEX: /^[a-zA-Z0-9._@+-]+$/,
        EMAIL_REGEX: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
        SANITIZE_FILTER: { allowedTags: [], allowedAttributes: {} },
        PRIVILEGE_LEVELS_ENUM: {
            WEBMASTER: 1,
            MODERATOR: 2,
            EDITOR: 3
        },
        EMPTY_STRING: '',
        PASSWORD_MIN_LENGTH: '8',
        HAS_UPPERCASE_REGEX: /[A-Z]/,
        HAS_LOWERCASE_REGEX: /[a-z]/,
        HAS_NUMBERS_REGEX: /\d/,
        HAS_SPECIAL_CHAR_REGEX: /[!@#$%^&*()]/
    }
}));

const request = require('supertest');
const express = require('express');

// Get mocked modules
const mockPost = require('../../../server/models/posts');
const mockUser = require('../../../server/models/user');
const mockComment = require('../../../server/models/comments');
const mockSiteConfig = require('../../../server/models/config');
const mockJwt = require('jsonwebtoken');
const mockBcrypt = require('bcrypt');
const mockValidations = require('../../../utils/validations');
const mockOpenRouter = require('../../../utils/openRouterIntegration');
const mockMongoose = require('mongoose');
const mockPostCache = require('../../../utils/postCache');

describe('Admin Route Tests for 90%+ Coverage', () => {
    let app;
    let adminRouter;

    beforeAll(() => {
        // Create Express app
        app = express();
        app.use(express.json());
        app.use(express.urlencoded({ extended: true }));

        // Mock middleware
        app.use((req, res, next) => {
            req.flash = jest.fn();
            req.cookies = { token: 'valid-token' };
            res.cookie = jest.fn();
            res.clearCookie = jest.fn();
            
            // Better redirect mock that doesn't cause header conflicts
            const originalRedirect = res.redirect;
            res.redirect = jest.fn((url) => {
                res.statusCode = 302;
                res.setHeader('Location', url);
                res.end(JSON.stringify({ redirect: url }));
                return res;
            });
            
            // Better render mock
            res.render = jest.fn((view, data) => {
                res.statusCode = 200;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({ view, data }));
                return res;
            });
            
            next();
        });

        // Import router after mocks are set up
        adminRouter = require('../../../server/routes/admin');
        app.use('/', adminRouter);
    });

    beforeEach(() => {
        jest.clearAllMocks();

        // Setup default mocks
        mockJwt.verify.mockReturnValue({ userId: 'user123' });
        mockJwt.sign.mockReturnValue('test-jwt-token');
        mockBcrypt.hash.mockResolvedValue('hashedpassword');
        mockBcrypt.compare.mockResolvedValue(true);
        mockPostSave.mockResolvedValue();
        mockUserSave.mockResolvedValue();
        mockConfigSave.mockResolvedValue();
        mockValidations.isValidURI.mockReturnValue(true);
        mockValidations.parseTags.mockReturnValue(['tag1']);
        mockValidations.createUniqueId.mockReturnValue('test-post');
        mockMongoose.Types.ObjectId.isValid.mockReturnValue(true);
    });

    describe('Basic Routes', () => {
        test('GET /admin should render admin panel', async () => {
            const response = await request(app)
                .get('/admin')
                .expect(200);

            expect(response.body.view).toBe('admin/index');
            expect(response.body.data.locals.title).toBe('Admin Panel');
        });

        test('POST /logout should clear cookie and redirect', async () => {
            const response = await request(app)
                .post('/logout')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });
    });

    describe('Registration', () => {
        test('POST /register should create user successfully', async () => {
            mockUser.findOne.mockResolvedValue(null);
            mockUser.create.mockResolvedValue({ username: 'testuser', name: 'Test User' });

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
            expect(mockUser.create).toHaveBeenCalled();
        });

        test('POST /register should handle empty fields', async () => {
            const response = await request(app)
                .post('/register')
                .send({
                    username: '',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /register should handle invalid username', async () => {
            const response = await request(app)
                .post('/register')
                .send({
                    username: 'invalid username!',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /register should handle existing username', async () => {
            mockUser.findOne.mockResolvedValue({ username: 'testuser' });

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /register should handle password mismatch', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'DifferentPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /register should handle weak password', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'weak',
                    name: 'Test User',
                    confirm_password: 'weak'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /register should handle registration disabled', async () => {
            // Create app with registration disabled
            const app2 = express();
            app2.use(express.json());
            app2.use(express.urlencoded({ extended: true }));
            app2.use((req, res, next) => {
                req.flash = jest.fn();
                req.cookies = { token: 'valid-token' };
                res.locals.siteConfig = { isRegistrationEnabled: false };
                res.cookie = jest.fn();
                res.clearCookie = jest.fn();
                res.render = jest.fn((view, data) => res.status(200).json({ view, data }));
                res.redirect = jest.fn((url) => res.status(302).json({ redirect: url }));
                next();
            });
            app2.use('/', adminRouter);

            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app2)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /register should handle user creation errors', async () => {
            mockUser.findOne.mockResolvedValue(null);
            mockUser.create.mockRejectedValue(new Error('Database error'));

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });
    });

    describe('Login', () => {
        test('POST /admin should login successfully', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser',
                name: 'Test User',
                password: 'hashedpassword',
                isPasswordReset: false
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin')
                .send({
                    username: 'testuser',
                    password: 'password123'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin should handle empty credentials', async () => {
            const response = await request(app)
                .post('/admin')
                .send({
                    username: '',
                    password: 'password123'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /admin should handle non-string username', async () => {
            const response = await request(app)
                .post('/admin')
                .send({
                    username: 123,
                    password: 'password123'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /admin should handle non-existent user', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/admin')
                .send({
                    username: 'nonexistent',
                    password: 'password123'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /admin should handle password reset users', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin')
                .send({
                    username: 'testuser',
                    password: 'password123'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /admin should handle invalid password', async () => {
            const mockUserData = {
                username: 'testuser',
                password: 'hashedpassword',
                isPasswordReset: false
            };

            mockUser.findOne.mockResolvedValue(mockUserData);
            mockBcrypt.compare.mockResolvedValue(false);

            const response = await request(app)
                .post('/admin')
                .send({
                    username: 'testuser',
                    password: 'wrongpassword'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });
    });

    describe('Dashboard', () => {
        test('GET /dashboard should render for editor', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'editor',
                privilege: 1
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.find.mockResolvedValue([{ title: 'Post 1', author: 'editor' }]);

            const response = await request(app)
                .get('/dashboard')
                .expect(200);

            expect(response.body.view).toBe('admin/dashboard');
        });

        test('GET /dashboard should render for moderator', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'moderator',
                privilege: 2
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.find.mockResolvedValue([{ title: 'Post 1' }]);

            const response = await request(app)
                .get('/dashboard')
                .expect(200);

            expect(response.body.view).toBe('admin/dashboard');
        });

        test('GET /dashboard should render for webmaster', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.find.mockResolvedValue([]);

            const response = await request(app)
                .get('/dashboard')
                .expect(200);

            expect(response.body.view).toBe('admin/dashboard');
        });

        test('GET /dashboard should handle user not found', async () => {
            mockUser.findById.mockResolvedValue(null);

            const response = await request(app)
                .get('/dashboard')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('GET /dashboard should handle invalid privilege', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'user',
                privilege: 999
            };

            mockUser.findById.mockResolvedValue(mockUserData);

            const response = await request(app)
                .get('/dashboard')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('GET /dashboard should handle database errors', async () => {
            mockUser.findById.mockRejectedValue(new Error('Database error'));

            const response = await request(app)
                .get('/dashboard')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });
    });

    describe('Post Management', () => {
        test('GET /admin/add-post should render add post page', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser',
                privilege: 1
            };

            mockUser.findById.mockResolvedValue(mockUserData);

            const response = await request(app)
                .get('/admin/add-post')
                .expect(200);

            expect(response.body.view).toBe('admin/add-post');
        });

        test('GET /admin/add-post should handle user not found', async () => {
            mockUser.findById.mockResolvedValue(null);

            const response = await request(app)
                .get('/admin/add-post')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /admin/add-post should create post successfully', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description',
                    tags: 'tag1,tag2',
                    thumbnailImageURI: 'https://example.com/image.jpg'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
            expect(mockPostSave).toHaveBeenCalled();
        });

        test('POST /admin/add-post should handle missing fields', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: '',
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/add-post should handle field length violations', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: 'A'.repeat(100),
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/add-post should handle unique ID generation failure', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue({ uniqueId: 'test-post' });

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/add-post should handle duplicate uniqueId error', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(null);
            mockPostSave.mockRejectedValue({
                code: 11000,
                keyPattern: { uniqueId: 1 }
            });

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(409);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/add-post should handle save errors', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(null);
            mockPostSave.mockRejectedValue(new Error('Save error'));

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });
    });

    describe('Post Editing', () => {
        test('GET /edit-post/:uniqueId should render edit page', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser',
                privilege: 1
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);

            const response = await request(app)
                .get('/edit-post/test-post')
                .expect(200);

            expect(response.body.view).toBe('admin/edit-post');
        });

        test('GET /edit-post/:uniqueId should handle post not found', async () => {
            mockPost.findOne.mockResolvedValue(null);

            const response = await request(app)
                .get('/edit-post/nonexistent')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('PUT /edit-post/:uniqueId should update post successfully', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser',
                privilege: 1
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Old Title',
                uniqueId: 'old-title'
            };

            const mockUpdatedPost = {
                _id: 'post123',
                title: 'New Title',
                uniqueId: 'new-title'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);
            mockPost.findByIdAndUpdate.mockResolvedValue(mockUpdatedPost);
            mockPost.findById.mockResolvedValue(mockUpdatedPost);
            mockValidations.createUniqueId.mockReturnValue('new-title');

            const response = await request(app)
                .put('/edit-post/old-title')
                .send({
                    title: 'New Title',
                    markdownbody: 'Updated content',
                    desc: 'Updated description',
                    tags: 'tag1',
                    thumbnailImageURI: 'https://example.com/new.jpg'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
            expect(mockPostCache.invalidateCache).toHaveBeenCalledWith('old-title');
        });

        test('PUT /edit-post/:uniqueId should handle user not found', async () => {
            mockUser.findById.mockResolvedValue(null);

            const response = await request(app)
                .put('/edit-post/test-post')
                .send({
                    title: 'New Title',
                    markdownbody: 'Updated content',
                    desc: 'Updated description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('PUT /edit-post/:uniqueId should handle post not found', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(null);

            const response = await request(app)
                .put('/edit-post/nonexistent')
                .send({
                    title: 'New Title',
                    markdownbody: 'Updated content',
                    desc: 'Updated description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('PUT /edit-post/:uniqueId should handle missing required fields', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);

            const response = await request(app)
                .put('/edit-post/test-post')
                .send({
                    title: '',
                    markdownbody: 'Updated content',
                    desc: 'Updated description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/edit-post/test-post');
        });

        test('PUT /edit-post/:uniqueId should handle field length violations', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);

            const response = await request(app)
                .put('/edit-post/test-post')
                .send({
                    title: 'A'.repeat(100),
                    markdownbody: 'Updated content',
                    desc: 'Updated description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/edit-post/test-post');
        });

        test('PUT /edit-post/:uniqueId should handle moderator approval toggle', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'moderator',
                privilege: 2
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            const mockUpdatedPost = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);
            mockPost.findByIdAndUpdate.mockResolvedValue(mockUpdatedPost);
            mockPost.findById.mockResolvedValue(mockUpdatedPost);

            const response = await request(app)
                .put('/edit-post/test-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description',
                    isApproved: 'on'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('PUT /edit-post/:uniqueId should handle update failure', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);
            mockPost.findByIdAndUpdate.mockResolvedValue(mockPostData);
            mockPost.findById.mockResolvedValue(null);

            const response = await request(app)
                .put('/edit-post/test-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/edit-post/test-post');
        });
    });

    describe('Post Deletion', () => {
        test('DELETE /delete-post/:uniqueId should delete post successfully', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);
            mockPost.deleteOne.mockResolvedValue({ deletedCount: 1 });
            mockComment.deleteMany.mockResolvedValue({ deletedCount: 5 });

            const response = await request(app)
                .delete('/delete-post/test-post')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
            expect(mockPostCache.invalidateCache).toHaveBeenCalledWith('test-post');
            expect(mockComment.deleteMany).toHaveBeenCalledWith({ postId: 'post123' });
        });

        test('DELETE /delete-post/:uniqueId should handle user not found', async () => {
            mockUser.findById.mockResolvedValue(null);

            const response = await request(app)
                .delete('/delete-post/test-post')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('DELETE /delete-post/:uniqueId should handle post not found', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(null);

            const response = await request(app)
                .delete('/delete-post/nonexistent')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('DELETE /delete-post/:uniqueId should handle deletion errors', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);
            mockPost.deleteOne.mockRejectedValue(new Error('Delete error'));
            mockComment.deleteMany.mockResolvedValue({ deletedCount: 0 });

            const response = await request(app)
                .delete('/delete-post/test-post')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });
    });

    describe('Webmaster Panel', () => {
        test('GET /admin/webmaster should render for webmaster', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUsers = [
                { _id: 'user1', username: 'user1', privilege: 1 },
                { _id: 'user2', username: 'user2', privilege: 2 }
            ];

            mockUser.findById.mockResolvedValue(mockWebmaster);
            mockUser.find.mockResolvedValue(mockUsers);

            const response = await request(app)
                .get('/admin/webmaster')
                .expect(200);

            expect(response.body.view).toBe('admin/webmaster');
        });

        test('GET /admin/webmaster should reject non-webmaster', async () => {
            const mockUser1 = {
                _id: 'user123',
                username: 'user',
                privilege: 1
            };

            mockUser.findById.mockResolvedValue(mockUser1);

            const response = await request(app)
                .get('/admin/webmaster')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('GET /admin/webmaster should handle user not found', async () => {
            mockUser.findById.mockResolvedValue(null);

            const response = await request(app)
                .get('/admin/webmaster')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('POST /edit-site-config should update config successfully', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);
            mockSiteConfig.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/edit-site-config')
                .send({
                    siteName: 'Updated Blog',
                    siteAdminEmail: 'admin@example.com',
                    defaultPaginationLimit: '10',
                    searchLimit: '20',
                    siteDefaultThumbnailUri: 'https://example.com/thumb.jpg',
                    homepageWelcomeImage: 'https://example.com/welcome.jpg',
                    isRegistrationEnabled: 'on',
                    isCommentsEnabled: 'on',
                    isCaptchaEnabled: 'on',
                    isAISummerizerEnabled: 'on'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
        });

        test('POST /edit-site-config should update existing config', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockExistingConfig = {
                siteDefaultThumbnailUri: 'https://old.com/thumb.jpg',
                homepageWelcomeImage: 'https://old.com/welcome.jpg'
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);
            mockSiteConfig.findOne.mockResolvedValue(mockExistingConfig);
            mockSiteConfig.findOneAndUpdate.mockResolvedValue(mockExistingConfig);

            const response = await request(app)
                .post('/edit-site-config')
                .send({
                    siteName: 'Updated Blog',
                    siteAdminEmail: 'admin@example.com',
                    defaultPaginationLimit: '10',
                    searchLimit: '20'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
            expect(mockSiteConfig.findOneAndUpdate).toHaveBeenCalled();
        });

        test('POST /edit-site-config should reject non-webmaster', async () => {
            const mockUser1 = {
                _id: 'user123',
                username: 'user',
                privilege: 1
            };

            mockUser.findById.mockResolvedValue(mockUser1);

            const response = await request(app)
                .post('/edit-site-config')
                .send({
                    siteName: 'Hacked Blog'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /edit-site-config should handle invalid email', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);

            const response = await request(app)
                .post('/edit-site-config')
                .send({
                    siteName: 'Updated Blog',
                    siteAdminEmail: 'invalid-email',
                    defaultPaginationLimit: '10',
                    searchLimit: '20'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /edit-site-config should handle invalid pagination limit', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);

            const response = await request(app)
                .post('/edit-site-config')
                .send({
                    siteName: 'Updated Blog',
                    siteAdminEmail: 'admin@example.com',
                    defaultPaginationLimit: '200',
                    searchLimit: '20'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /edit-site-config should handle invalid search limit', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);

            const response = await request(app)
                .post('/edit-site-config')
                .send({
                    siteName: 'Updated Blog',
                    siteAdminEmail: 'admin@example.com',
                    defaultPaginationLimit: '10',
                    searchLimit: '100'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });
    });

    describe('User Management', () => {
        test('DELETE /delete-user/:id should delete user successfully', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToDelete = {
                _id: 'user456',
                username: 'userToDelete'
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToDelete);
            mockUser.deleteOne.mockResolvedValue({ deletedCount: 1 });

            const response = await request(app)
                .delete('/delete-user/user456')
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
            expect(mockUser.deleteOne).toHaveBeenCalledWith({ _id: 'user456' });
        });

        test('DELETE /delete-user/:id should reject non-webmaster', async () => {
            const mockUser1 = {
                _id: 'user123',
                username: 'user',
                privilege: 1
            };

            mockUser.findById.mockResolvedValue(mockUser1);

            const response = await request(app)
                .delete('/delete-user/user456')
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
        });

        test('DELETE /delete-user/:id should handle invalid user ID', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);
            mockMongoose.Types.ObjectId.isValid.mockReturnValue(false);

            const response = await request(app)
                .delete('/delete-user/invalid-id')
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
        });

        test('DELETE /delete-user/:id should handle user not found', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(null);

            const response = await request(app)
                .delete('/delete-user/nonexistent')
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
        });

        test('DELETE /delete-user/:id should prevent self-deletion', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);

            const response = await request(app)
                .delete('/delete-user/webmaster123')
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/webmaster123');
        });

        test('GET /edit-user/:id should render edit user page', async () => {
            const mockCurrentUser = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockSelectedUser = {
                _id: 'user456',
                username: 'selecteduser',
                name: 'Selected User'
            };

            mockUser.findById.mockResolvedValue(mockCurrentUser);
            mockUser.findOne.mockResolvedValue(mockSelectedUser);

            const response = await request(app)
                .get('/edit-user/user456')
                .expect(200);

            expect(response.body.view).toBe('admin/edit-user');
        });

        test('GET /edit-user/:id should handle invalid user ID', async () => {
            mockMongoose.Types.ObjectId.isValid.mockReturnValue(false);

            const response = await request(app)
                .get('/edit-user/invalid-id')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('GET /edit-user/:id should handle user not found', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .get('/edit-user/nonexistent')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('PUT /edit-user/:id should update user successfully', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToUpdate = {
                _id: 'user456',
                username: 'userToUpdate',
                name: 'Old Name',
                privilege: 1,
                save: mockUserSave
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToUpdate);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: 'New Name',
                    privilege: '2'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
            expect(mockUserSave).toHaveBeenCalled();
        });

        test('PUT /edit-user/:id should handle password reset', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToUpdate = {
                _id: 'user456',
                username: 'userToUpdate',
                name: 'User Name',
                privilege: 1,
                save: mockUserSave
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToUpdate);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: 'User Name',
                    privilege: '1',
                    adminTempPassword: 'TempPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/webmaster');
            expect(mockBcrypt.hash).toHaveBeenCalledWith('TempPass123!', 10);
        });

        test('PUT /edit-user/:id should reject non-webmaster', async () => {
            const mockUser1 = {
                _id: 'user123',
                username: 'user',
                privilege: 1
            };

            mockUser.findById.mockResolvedValue(mockUser1);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: 'Hacked Name'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/user456');
        });

        test('PUT /edit-user/:id should handle invalid user ID', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            mockUser.findById.mockResolvedValue(mockWebmaster);
            mockMongoose.Types.ObjectId.isValid.mockReturnValue(false);

            const response = await request(app)
                .put('/edit-user/invalid-id')
                .send({
                    name: 'New Name'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/invalid-id');
        });

        test('PUT /edit-user/:id should handle missing name field', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToUpdate = {
                _id: 'user456',
                username: 'userToUpdate'
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToUpdate);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: '',
                    privilege: '1'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/user456');
        });

        test('PUT /edit-user/:id should handle weak temporary password', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToUpdate = {
                _id: 'user456',
                username: 'userToUpdate',
                name: 'User Name'
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToUpdate);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: 'User Name',
                    privilege: '1',
                    adminTempPassword: 'weak'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/user456');
        });

        test('PUT /edit-user/:id should handle invalid privilege level', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToUpdate = {
                _id: 'user456',
                username: 'userToUpdate',
                name: 'User Name',
                privilege: 1
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToUpdate);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: 'User Name',
                    privilege: '999'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/user456');
        });

        test('PUT /edit-user/:id should handle save errors', async () => {
            const mockWebmaster = {
                _id: 'webmaster123',
                username: 'webmaster',
                privilege: 3
            };

            const mockUserToUpdate = {
                _id: 'user456',
                username: 'userToUpdate',
                name: 'Old Name',
                privilege: 1,
                save: jest.fn().mockRejectedValue(new Error('Save error'))
            };

            mockUser.findById.mockResolvedValueOnce(mockWebmaster).mockResolvedValueOnce(mockUserToUpdate);

            const response = await request(app)
                .put('/edit-user/user456')
                .send({
                    name: 'New Name',
                    privilege: '2'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/edit-user/user456');
        });
    });

    describe('AI Summary and Password Reset', () => {
        test('POST /admin/generate-post-summary should generate summary', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockOpenRouter.summarizeMarkdownBody.mockResolvedValue({
                summary: 'Generated summary',
                attribute: '\n\n*Generated by AI*'
            });

            const response = await request(app)
                .post('/admin/generate-post-summary')
                .send({
                    markdownbody: 'This is a test post content'
                })
                .expect(200);

            expect(response.body.code).toBe(200);
        });

        test('POST /admin/generate-post-summary should handle errors', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockOpenRouter.summarizeMarkdownBody.mockRejectedValue(new Error('AI service error'));

            const response = await request(app)
                .post('/admin/generate-post-summary')
                .send({
                    markdownbody: 'This is a test post content'
                })
                .expect(500);

            expect(response.body.code).toBe(500);
        });

        test('GET /admin/reset-password should render reset page', async () => {
            const response = await request(app)
                .get('/admin/reset-password')
                .expect(200);

            expect(response.body.view).toBe('admin/reset-password');
        });

        test('POST /admin/reset-password should reset password successfully', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true,
                adminTempPassword: 'hashedtemppassword',
                password: 'Qm9jY2hpIHRoZSBSb2Nr',
                save: mockUserSave
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'TempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
            expect(mockUserSave).toHaveBeenCalled();
        });

        test('POST /admin/reset-password should handle missing fields', async () => {
            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: '',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle invalid username', async () => {
            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'invalid username!',
                    tempPassword: 'TempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle user not found', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'nonexistent',
                    tempPassword: 'TempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle user not approved for reset', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: false,
                adminTempPassword: '',
                password: 'normalpassword'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'TempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should prevent reusing temp password', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true,
                adminTempPassword: 'hashedtemppassword',
                password: 'Qm9jY2hpIHRoZSBSb2Nr'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'TempPass123!',
                    newPassword: 'TempPass123!',
                    confirmPassword: 'TempPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle weak new password', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true,
                adminTempPassword: 'hashedtemppassword',
                password: 'Qm9jY2hpIHRoZSBSb2Nr'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'TempPass123!',
                    newPassword: 'weak',
                    confirmPassword: 'weak'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle password confirmation mismatch', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true,
                adminTempPassword: 'hashedtemppassword',
                password: 'Qm9jY2hpIHRoZSBSb2Nr'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'TempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'DifferentPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle invalid temp password', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true,
                adminTempPassword: 'hashedtemppassword',
                password: 'Qm9jY2hpIHRoZSBSb2Nr'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);
            mockBcrypt.compare.mockResolvedValue(false);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'WrongTempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });

        test('POST /admin/reset-password should handle save errors', async () => {
            const mockUserData = {
                username: 'testuser',
                isPasswordReset: true,
                adminTempPassword: 'hashedtemppassword',
                password: 'Qm9jY2hpIHRoZSBSb2Nr',
                save: jest.fn().mockRejectedValue(new Error('Save error'))
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/reset-password')
                .send({
                    username: 'testuser',
                    tempPassword: 'TempPass123!',
                    newPassword: 'NewPass123!',
                    confirmPassword: 'NewPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/reset-password');
        });
    });

    describe('User Profile Management', () => {
        test('GET /admin/profile/:username should render profile page', async () => {
            const mockUserData = {
                id: 'user123',
                _id: 'user123',
                username: 'testuser',
                name: 'Test User',
                privilege: 1
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .get('/admin/profile/testuser')
                .expect(200);

            expect(response.body.view).toBe('admin/edit-my-profile');
        });

        test('GET /admin/profile/:username should handle invalid username', async () => {
            const response = await request(app)
                .get('/admin/profile/invalid username!')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('GET /admin/profile/:username should handle user not found', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .get('/admin/profile/nonexistent')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('GET /admin/profile/:username should prevent accessing other profiles', async () => {
            const mockUserData = {
                id: 'different123',
                _id: 'different123',
                username: 'otheruser',
                name: 'Other User'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .get('/admin/profile/otheruser')
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/edit-profile/:username should update profile', async () => {
            const mockUserData = {
                id: 'user123',
                _id: 'user123',
                username: 'testuser',
                name: 'Old Name',
                description: 'Old description',
                portfolioLink: 'https://old.com',
                save: mockUserSave
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/edit-profile/testuser')
                .send({
                    name: 'New Name',
                    description: 'New description',
                    portfolioLink: 'https://new.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
            expect(mockUserSave).toHaveBeenCalled();
        });

        test('POST /admin/edit-profile/:username should handle invalid username', async () => {
            const response = await request(app)
                .post('/admin/edit-profile/invalid username!')
                .send({
                    name: 'New Name',
                    description: 'New description',
                    portfolioLink: 'https://new.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/edit-profile/:username should handle user not found', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/admin/edit-profile/nonexistent')
                .send({
                    name: 'New Name',
                    description: 'New description',
                    portfolioLink: 'https://new.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/edit-profile/:username should prevent editing other profiles', async () => {
            const mockUserData = {
                id: 'different123',
                _id: 'different123',
                username: 'otheruser',
                name: 'Other User'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/edit-profile/otheruser')
                .send({
                    name: 'Hacked Name',
                    description: 'Hacked description',
                    portfolioLink: 'https://hacked.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/edit-profile/:username should handle missing fields', async () => {
            const mockUserData = {
                id: 'user123',
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/edit-profile/testuser')
                .send({
                    name: '',
                    description: 'New description',
                    portfolioLink: 'https://new.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/edit-profile/:username should handle field length violations', async () => {
            const mockUserData = {
                id: 'user123',
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/edit-profile/testuser')
                .send({
                    name: 'A'.repeat(200),
                    description: 'New description',
                    portfolioLink: 'https://new.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('POST /admin/edit-profile/:username should handle invalid portfolio link', async () => {
            const mockUserData = {
                id: 'user123',
                _id: 'user123',
                username: 'testuser',
                name: 'Test User',
                description: 'Old description',
                portfolioLink: 'https://old.com',
                save: mockUserSave
            };

            mockUser.findOne.mockResolvedValue(mockUserData);
            mockValidations.isValidURI.mockReturnValue(false);

            const response = await request(app)
                .post('/admin/edit-profile/testuser')
                .send({
                    name: 'New Name',
                    description: 'New description',
                    portfolioLink: 'invalid-url'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
            expect(mockUserSave).toHaveBeenCalled();
        });

        test('POST /admin/edit-profile/:username should handle save errors', async () => {
            const mockUserData = {
                id: 'user123',
                _id: 'user123',
                username: 'testuser',
                name: 'Old Name',
                description: 'Old description',
                portfolioLink: 'https://old.com',
                save: jest.fn().mockRejectedValue(new Error('Save error'))
            };

            mockUser.findOne.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/edit-profile/testuser')
                .send({
                    name: 'New Name',
                    description: 'New description',
                    portfolioLink: 'https://new.com'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });
    });

    describe('Authentication Middleware', () => {
        test('should redirect to /admin when no token provided', async () => {
            // Create app without token
            const app2 = express();
            app2.use(express.json());
            app2.use(express.urlencoded({ extended: true }));
            app2.use((req, res, next) => {
                req.flash = jest.fn();
                req.cookies = {}; // No token
                res.cookie = jest.fn();
                res.clearCookie = jest.fn();
                res.render = jest.fn((view, data) => res.status(200).json({ view, data }));
                res.redirect = jest.fn((url) => res.status(302).json({ redirect: url }));
                next();
            });
            app2.use('/', adminRouter);

            const response = await request(app2)
                .get('/dashboard')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('should redirect to /admin when invalid token provided', async () => {
            mockJwt.verify.mockImplementation(() => {
                throw new Error('Invalid token');
            });

            // Create app with invalid token handling
            const app2 = express();
            app2.use(express.json());
            app2.use(express.urlencoded({ extended: true }));
            app2.use((req, res, next) => {
                req.flash = jest.fn();
                req.cookies = { token: 'invalid-token' };
                res.cookie = jest.fn();
                res.clearCookie = jest.fn();
                res.render = jest.fn((view, data) => res.status(200).json({ view, data }));
                res.redirect = jest.fn((url) => res.status(302).json({ redirect: url }));
                next();
            });
            app2.use('/', adminRouter);

            const response = await request(app2)
                .get('/dashboard')
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });
    });

    describe('Edge Cases and Coverage', () => {
        test('should handle production environment logging', async () => {
            const originalEnv = process.env.NODE_ENV;
            process.env.NODE_ENV = 'production';

            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'invalid username!',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');

            process.env.NODE_ENV = originalEnv;
        });

        test('should handle non-production environment logging', async () => {
            const originalEnv = process.env.NODE_ENV;
            process.env.NODE_ENV = 'development';

            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            const mockPostData = {
                _id: 'post123',
                title: 'Test Post',
                uniqueId: 'test-post'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(mockPostData);

            const response = await request(app)
                .put('/edit-post/test-post')
                .send({
                    title: '',
                    markdownbody: 'Updated content',
                    desc: 'Updated description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin/edit-post/test-post');

            process.env.NODE_ENV = originalEnv;
        });

        test('should handle missing site config gracefully', async () => {
            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);
            mockPost.findOne.mockResolvedValue(null);
            mockValidations.isValidURI.mockReturnValue(false);

            // Create app without site config
            const app2 = express();
            app2.use(express.json());
            app2.use(express.urlencoded({ extended: true }));
            app2.use((req, res, next) => {
                req.flash = jest.fn();
                req.cookies = { token: 'valid-token' };
                res.locals.siteConfig = null;
                res.cookie = jest.fn();
                res.clearCookie = jest.fn();
                res.render = jest.fn((view, data) => res.status(200).json({ view, data }));
                res.redirect = jest.fn((url) => res.status(302).json({ redirect: url }));
                next();
            });
            app2.use('/', adminRouter);

            const response = await request(app2)
                .post('/admin/add-post')
                .send({
                    title: 'Test Post',
                    markdownbody: 'Test content',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('should handle markdown conversion errors', async () => {
            const mockMarked = require('marked');
            mockMarked.parse.mockImplementation(() => {
                throw new Error('Markdown error');
            });

            const mockUserData = {
                _id: 'user123',
                username: 'testuser'
            };

            mockUser.findById.mockResolvedValue(mockUserData);

            const response = await request(app)
                .post('/admin/add-post')
                .send({
                    title: 'Test Post',
                    markdownbody: '# Test',
                    desc: 'Test description'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/dashboard');
        });

        test('should validate strong passwords through registration', async () => {
            mockUser.findOne.mockResolvedValue(null);
            mockUser.create.mockResolvedValue({
                username: 'testuser',
                name: 'Test User'
            });

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'StrongPass123!',
                    name: 'Test User',
                    confirm_password: 'StrongPass123!'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });

        test('should reject weak passwords through registration', async () => {
            mockUser.findOne.mockResolvedValue(null);

            const response = await request(app)
                .post('/register')
                .send({
                    username: 'testuser',
                    password: 'weak',
                    name: 'Test User',
                    confirm_password: 'weak'
                })
                .expect(302);

            expect(response.body.redirect).toBe('/admin');
        });
    });
});