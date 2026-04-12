const mongoose = require('mongoose');
const https = require('node:https');
const logger = require('../../../utils/logger');
const connectDB = require('../../../server/config/db');

jest.mock('mongoose');
jest.mock('node:https');
jest.mock('../../../utils/logger', () => ({
    info: jest.fn(),
    error: jest.fn(),
    warn: jest.fn()
}));

describe('connectDB Middleware', () => {
    let req, res, next;

    beforeEach(() => {
        req = {};
        res = {
            status: jest.fn().mockReturnThis(),
            render: jest.fn()
        };
        next = jest.fn();
        jest.clearAllMocks();
        
        // Mock default environment
        process.env.MONGO_DB_URI = 'mongodb://localhost:27017/test';
    });

    test('should call next immediately if already connected (readyState === 1)', async () => {
        mongoose.connection = { readyState: 1 };
        
        await connectDB(req, res, next);
        
        expect(next).toHaveBeenCalledTimes(1);
        expect(mongoose.connect).not.toHaveBeenCalled();
    });

    test('should connect to database and call next if successful', async () => {
        mongoose.connection = { readyState: 0, host: 'localhost' };
        mongoose.connect.mockResolvedValue({
            connection: { host: 'localhost' }
        });

        await connectDB(req, res, next);

        expect(mongoose.set).toHaveBeenCalledWith('strictQuery', false);
        expect(mongoose.connect).toHaveBeenCalledWith(process.env.MONGO_DB_URI);
        expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('DB Connected: localhost'));
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('should retry connection if it fails initially', async () => {
        mongoose.connection = { readyState: 0 };
        // Fail first time, succeed second time
        mongoose.connect
            .mockRejectedValueOnce(new Error('Connection failed'))
            .mockResolvedValueOnce({
                connection: { host: 'localhost' }
            });

        // Mock https.get to simulate IP fetch success
        const mockResp = {
            on: jest.fn((event, cb) => {
                if (event === 'data') cb('127.0.0.1');
                if (event === 'end') cb();
                return mockResp;
            })
        };
        const mockRequest = {
            on: jest.fn()
        };
        https.get.mockImplementation((url, cb) => {
            cb(mockResp);
            return mockRequest;
        });

        await connectDB(req, res, next);

        expect(mongoose.connect).toHaveBeenCalledTimes(2);
        expect(logger.error).toHaveBeenCalledWith(expect.stringContaining('attempt 1 failed:'), 'Connection failed');
        expect(logger.info).toHaveBeenCalledWith('My public IP address is: 127.0.0.1');
        expect(logger.info).toHaveBeenCalledWith('Retrying in 0.5 seconds...');
        expect(next).toHaveBeenCalledTimes(1);
    });

    test('should render error page after max retries', async () => {
        mongoose.connection = { readyState: 0 };
        mongoose.connect.mockRejectedValue(new Error('Connection failed'));

        // Mock https.get to simulate IP fetch error
        const mockRequest = {
            on: jest.fn((event, cb) => {
                if (event === 'error') cb(new Error('IP fetch failed'));
                return mockRequest;
            })
        };
        https.get.mockReturnValue(mockRequest);

        await connectDB(req, res, next);

        // Max retries = 3 retry attempts + 1 initial = 4 total attempts
        expect(mongoose.connect).toHaveBeenCalledTimes(4);
        expect(logger.error).toHaveBeenCalledWith('Max retry attempts reached. Rendering error page...');
        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.render).toHaveBeenCalledWith('error', { locals: { config: {} } });
        expect(next).not.toHaveBeenCalled();
    });
    
    test('should handle completely synchronous https setup errors silently', async () => {
        mongoose.connection = { readyState: 0 };
        mongoose.connect.mockRejectedValue(new Error('Connection failed'));

        https.get.mockImplementation(() => {
            throw new Error('Sync https error');
        });

        await connectDB(req, res, next);

        expect(logger.error).toHaveBeenCalledWith('Error during IP fetch setup:', 'Sync https error');
        expect(mongoose.connect).toHaveBeenCalledTimes(4);
    });
});
