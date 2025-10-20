const {
  isValidURI,
  isWebMaster,
  isValidTrackingScript,
  parseTags,
  createUniqueId
} = require('../../utils/validations');
const { CONSTANTS } = require('../../utils/constants');

describe('Validations Module', () => {
  describe('isValidURI', () => {
    test('should return true for valid HTTP URLs', () => {
      expect(isValidURI('http://example.com')).toBe(true);
      expect(isValidURI('https://example.com')).toBe(true);
      expect(isValidURI('https://subdomain.example.com/path')).toBe(true);
    });

    test('should return false for invalid URLs', () => {
      expect(isValidURI('')).toBe(false);
      expect(isValidURI('   ')).toBe(false);
      expect(isValidURI('javascript:alert(1)')).toBe(false);
      expect(isValidURI('data:text/html,<script>alert(1)</script>')).toBe(false);
      expect(isValidURI('vbscript:msgbox(1)')).toBe(false);
      expect(isValidURI('ftp://example.com')).toBe(false);
    });

    test('should return false for URLs with suspicious patterns', () => {
      expect(isValidURI('https://example.com<script>')).toBe(false);
      expect(isValidURI('https://example.com"onload="alert(1)"')).toBe(false);
      expect(isValidURI('https://example.com;alert(1)')).toBe(false);
    });

    test('should return false for URLs without hostname', () => {
      expect(isValidURI('https://')).toBe(false);
      expect(isValidURI('http://')).toBe(false);
    });
  });

  describe('isWebMaster', () => {
    test('should return true for webmaster privilege', () => {
      const webmaster = { privilege: CONSTANTS.PRIVILEGE_LEVELS_ENUM.WEBMASTER };
      expect(isWebMaster(webmaster)).toBe(true);
    });

    test('should return false for non-webmaster privileges', () => {
      const moderator = { privilege: CONSTANTS.PRIVILEGE_LEVELS_ENUM.MODERATOR };
      const editor = { privilege: CONSTANTS.PRIVILEGE_LEVELS_ENUM.EDITOR };
      expect(isWebMaster(moderator)).toBe(false);
      expect(isWebMaster(editor)).toBe(false);
    });

    test('should return false for invalid user objects', () => {
      expect(isWebMaster(null)).toBe(false);
      expect(isWebMaster(undefined)).toBe(false);
      expect(isWebMaster({})).toBe(false);
      expect(isWebMaster({ privilege: 'invalid' })).toBe(false);
    });
  });

  describe('isValidTrackingScript', () => {
    const originalEnv = process.env.TRACKING_SCRIPT_ERROR_MSG;

    beforeEach(() => {
      process.env.TRACKING_SCRIPT_ERROR_MSG = 'Error on script validation';
    });

    afterEach(() => {
      process.env.TRACKING_SCRIPT_ERROR_MSG = originalEnv;
    });

    test('should return valid Google Analytics script', () => {
      const validGA = '<script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123"></script><script>gtag(\'config\', \'G-ABC123\');</script>';
      expect(isValidTrackingScript(validGA)).toBe(validGA);
    });

    test('should return error for invalid script types', () => {
      expect(isValidTrackingScript(123)).toBe('Error on script validation');
      expect(isValidTrackingScript(null)).toBe('Error on script validation');
      expect(isValidTrackingScript(undefined)).toBe('Error on script validation');
    });

    test('should return error for oversized scripts', () => {
      const largeScript = 'a'.repeat(5001);
      expect(isValidTrackingScript(largeScript)).toBe('Error on script validation');
    });

    test('should return error for invalid scripts', () => {
      const invalidScript = '<script>alert("malicious")</script>';
      expect(isValidTrackingScript(invalidScript)).toBe('Error on script validation');
    });

    test('should handle missing environment variable', () => {
      delete process.env.TRACKING_SCRIPT_ERROR_MSG;
      const invalidScript = 'invalid';
      expect(isValidTrackingScript(invalidScript)).toBe('Error on script validation');
    });
  });

  describe('parseTags', () => {
    test('should parse comma-separated tags correctly', () => {
      expect(parseTags('tag1,tag2,tag3')).toEqual(['tag1', 'tag2', 'tag3']);
      expect(parseTags('  tag1  ,  tag2  ,  tag3  ')).toEqual(['tag1', 'tag2', 'tag3']);
    });

    test('should sanitize HTML from tags', () => {
      expect(parseTags('tag1,<script>alert(1)</script>,tag3')).toEqual(['tag1', 'tag3']);
    });

    test('should remove special characters from tags', () => {
      expect(parseTags('tag@1,tag#2,tag$3')).toEqual(['tag1', 'tag2', 'tag3']);
    });

    test('should limit tag length to 30 characters', () => {
      const longTag = 'a'.repeat(50);
      expect(parseTags(longTag)).toEqual([longTag.substring(0, 30)]);
    });

    test('should filter out empty tags', () => {
      expect(parseTags('tag1,,tag3,   ,')).toEqual(['tag1', 'tag3']);
    });

    test('should return empty array for non-string input', () => {
      expect(parseTags(null)).toEqual([]);
      expect(parseTags(undefined)).toEqual([]);
      expect(parseTags(123)).toEqual([]);
    });
  });

  describe('createUniqueId', () => {
    test('should create unique ID from title', () => {
      const result = createUniqueId('Test Blog Post');
      expect(result).toMatch(/^test_blog_post_\d{4}$/);
    });

    test('should handle empty or invalid titles', () => {
      expect(createUniqueId('')).toMatch(/^null.*post.*title.*_\d{4}$/);
      expect(createUniqueId(null)).toMatch(/^null.*post.*title.*_\d{4}$/);
      expect(createUniqueId(undefined)).toMatch(/^null.*post.*title.*_\d{4}$/);
    });

    test('should sanitize HTML from title', () => {
      const result = createUniqueId('<script>alert(1)</script>Test');
      expect(result).toMatch(/^.*test.*_\d{4}$/);
    });

    test('should remove special characters and replace spaces', () => {
      const result = createUniqueId('Test @ Blog # Post $ Title');
      expect(result).toMatch(/^test.*blog.*post.*title.*_\d{4}$/);
    });

    test('should convert to lowercase', () => {
      const result = createUniqueId('TEST BLOG POST');
      expect(result).toMatch(/^test_blog_post_\d{4}$/);
    });
  });
});