module.exports = {
  testEnvironment: 'node',
  collectCoverage: true,
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  collectCoverageFrom: [
    'utils/constants.js',
    'utils/validations.js',
    'utils/cloudflareTurnstileServerVerify.js',
    'utils/rateLimiter.js',
    'server/routes/main.js',
    '!server/routes/admin.js',
    '!**/node_modules/**',
    '!coverage/**',
    '!jest.config.js'
  ],
  coverageThreshold: {
    global: {
      branches: 19,
      functions: 53,
      lines: 30,
      statements: 30
    },
    'utils/**/*.js': {
      branches: 90,
      functions: 100,
      lines: 90,
      statements: 90
    }
  },
  testMatch: [
    '**/tests/working-comprehensive.test.js',
    '**/tests/utils/cloudflareTurnstileServerVerify.test.js',
    '**/tests/utils/validations.test.js',
    '**/tests/utils/constants.test.js',
    '**/tests/utils/rateLimiter.test.js',
    '**/tests/utils/postCache.test.js',
    '**/tests/server/routes/main.test.js'
  ],
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],
  testTimeout: 30000
};