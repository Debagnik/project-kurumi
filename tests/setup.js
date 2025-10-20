// Global test setup
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
process.env.MONGO_DB_URI = 'mongodb://localhost:27017/test-db';
process.env.SESSION_SECRET = 'test-session-secret';
process.env.OPENROUTER_API_KEY = 'test-openrouter-key';
process.env.SYSTEM_PROMPT = 'Test system prompt';
process.env.LLM_MODEL = 'test-model';
process.env.USER_PROMPT = 'Test user prompt';
process.env.USER_PROMPT_2 = 'Test user prompt 2';
process.env.LLM_BASE_URL = 'https://test-api.example.com';
process.env.MAX_DESCRIPTION_LENGTH = '1000';
process.env.POST_CACHE_MAX_SIZE = '10';
process.env.POST_CACHE_TTL = '3600';
process.env.POST_HIT_RESET_INTERVAL_HOURS = '24';
process.env.MAX_COMMENTS_LIMIT = '10';
process.env.TRACKING_SCRIPT_ERROR_MSG = 'Invalid tracking script';
process.env.MAX_TITLE_LENGTH = '100';
process.env.MAX_BODY_LENGTH = '50000';
process.env.DEFAULT_POST_THUMBNAIL_LINK = 'https://via.placeholder.com/800x400';

// Suppress console logs during tests unless explicitly needed
const originalConsole = console;
global.console = {
  ...originalConsole,
  log: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
  info: jest.fn()
};

// Reset mocks after each test
afterEach(() => {
  jest.clearAllMocks();
});