const express = require('express');
const logger = require('../utils/logger');

jest.mock('mongoose', () => {
    const actualMongoose = jest.requireActual('mongoose');
    return {
        ...actualMongoose,
        connection: {
            once: jest.fn((event, cb) => {
                if (event === 'connected') {
                    cb();
                }
            }),
            getClient: jest.fn().mockReturnValue({ db: jest.fn() })
        }
    };
});

jest.mock('connect-mongo', () => ({
    create: jest.fn(() => ({}))
}));

jest.mock('express-session', () => {
    return jest.fn(() => (req, res, next) => next());
});

// Mock logger to avoid test console pollution
jest.mock('../utils/logger', () => ({
    info: jest.fn(),
    error: jest.fn()
}));

describe('app.js Server Entry', () => {
    let mockListen;
    let middlewares = [];

    beforeAll(() => {
        // Intercept app.use to grab inline middleware
        jest.spyOn(express.application, 'use').mockImplementation(function (fn) {
            middlewares.push(fn);
            return this;
        });

        // Prevent actual server from holding a port
        mockListen = jest.spyOn(express.application, 'listen').mockImplementation((port, cb) => {
            if (cb) cb();
            return { close: jest.fn() };
        });

        // Setup env
        process.env.PORT = '5001';
        process.env.SESSION_SECRET = 'test-secret';
        process.env.NODE_ENV = 'test';

        // Load app.js (executes initialization)
        require('../app.js');
    });

    afterAll(() => {
        jest.restoreAllMocks();
    });

    test('should initialize express app and start server', () => {
        expect(mockListen).toHaveBeenCalledWith('5001', expect.any(Function));
        // Verify logger was called by listen callback
        expect(logger.info).toHaveBeenCalledWith('App is listening to PORT 5001');
    });

    test('should handle flash messages middleware correctly', () => {
        // Flash middleware is usually defined simply as (req, res, next)
        const flashMiddleware = middlewares.find(mw => 
            typeof mw === 'function' && mw.toString().includes('res.locals.flash =')
        );
        expect(flashMiddleware).toBeDefined();

        const req = { flash: jest.fn((type) => type + '_message') };
        const res = { locals: {} };
        const next = jest.fn();

        flashMiddleware(req, res, next);
        
        expect(res.locals.flash).toEqual({
            success_msg: 'success_message',
            error_msg: 'error_message',
            info_msg: 'info_message'
        });
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('should handle CSRF errors in error handler middleware', () => {
        // Find CSRF error middleware (4 params: err, req, res, next)
        const csrfMiddleware = middlewares.find(mw => 
            typeof mw === 'function' && mw.length === 4 && mw.toString().includes('EBADCSRFTOKEN')
        );
        expect(csrfMiddleware).toBeDefined();

        const req = { path: '/test', ip: '127.0.0.1' };
        const res = { 
            status: jest.fn().mockReturnThis(), 
            json: jest.fn(),
            send: jest.fn()
        };
        const next = jest.fn();

        // 1. Non-CSRF error should be passed to next
        const normalError = new Error('Test error');
        csrfMiddleware(normalError, req, res, next);
        expect(next).toHaveBeenCalledWith(normalError);

        // 2. CSRF error should be caught and handled
        const csrfError = { code: 'EBADCSRFTOKEN' };
        csrfMiddleware(csrfError, req, res, next);
        
        expect(logger.error).toHaveBeenCalledWith('CSRF attempt detected:', expect.any(Object));
        expect(res.status).toHaveBeenCalledWith(403);
        expect(res.json).toHaveBeenCalled();
        expect(res.send).toHaveBeenCalledWith('Form tampered with');
    });

    test('should handle 404 responses in fallback middleware', () => {
        // 404 middleware is generally the last 3-param middleware with status(404)
        const notFoundMiddleware = middlewares.find(mw => 
            typeof mw === 'function' && mw.length === 3 && mw.toString().includes('.status(404)')
        );
        expect(notFoundMiddleware).toBeDefined();

        const req = { csrfToken: () => 'test-csrf-token' };
        const res = { 
            status: jest.fn().mockReturnThis(), 
            render: jest.fn(),
            locals: { siteConfig: { test: true } }
        };
        const next = jest.fn();

        notFoundMiddleware(req, res, next);
        
        expect(res.status).toHaveBeenCalledWith(404);
        expect(res.render).toHaveBeenCalledWith('404', {
            locals: {
                title: '404 - Page Not Found',
                description: '404 Not Found',
                config: { test: true }
            },
            csrfToken: 'test-csrf-token'
        });
    });
});
