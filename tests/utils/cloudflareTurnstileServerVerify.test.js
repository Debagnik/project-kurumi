const axios = require('axios');
const verifyCloudflareTurnstileToken = require('../../utils/cloudflareTurnstileServerVerify');

// Mock axios
jest.mock('axios');
const mockedAxios = axios;

describe('Cloudflare Turnstile Server Verify', () => {
  const originalEnv = process.env.NODE_ENV;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    process.env.NODE_ENV = originalEnv;
  });

  describe('verifyCloudflareTurnstileToken', () => {
    test('should return false when token is missing', async () => {
      const result = await verifyCloudflareTurnstileToken(null, '127.0.0.1', 'secret');
      expect(result).toBe(false);
    });

    test('should return false when secret key is missing', async () => {
      const result = await verifyCloudflareTurnstileToken('token', '127.0.0.1', null);
      expect(result).toBe(false);
    });

    test('should return true for successful verification', async () => {
      const mockResponse = {
        data: { success: true }
      };
      mockedAxios.post.mockResolvedValue(mockResponse);

      const result = await verifyCloudflareTurnstileToken('valid-token', '127.0.0.1', 'secret-key');
      
      expect(result).toBe(true);
      expect(mockedAxios.post).toHaveBeenCalledWith(
        'https://challenges.cloudflare.com/turnstile/v0/siteverify',
        expect.any(URLSearchParams),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
    });

    test('should return false for failed verification', async () => {
      const mockResponse = {
        data: { success: false, 'error-codes': ['invalid-input-response'] }
      };
      mockedAxios.post.mockResolvedValue(mockResponse);

      const result = await verifyCloudflareTurnstileToken('invalid-token', '127.0.0.1', 'secret-key');
      
      expect(result).toBe(false);
    });

    test('should handle network errors gracefully', async () => {
      mockedAxios.post.mockRejectedValue(new Error('Network error'));

      const result = await verifyCloudflareTurnstileToken('token', '127.0.0.1', 'secret-key');
      
      expect(result).toBe(false);
    });

    test('should log detailed response in non-production environment', async () => {
      process.env.NODE_ENV = 'development';
      const mockResponse = {
        data: { success: false, 'error-codes': ['timeout-or-duplicate'] }
      };
      mockedAxios.post.mockResolvedValue(mockResponse);

      await verifyCloudflareTurnstileToken('token', '127.0.0.1', 'secret-key');
      
      expect(console.log).toHaveBeenCalledWith('Turnstile verification response:', mockResponse.data);
    });

    test('should log only success status in production environment', async () => {
      process.env.NODE_ENV = 'production';
      const mockResponse = {
        data: { success: true }
      };
      mockedAxios.post.mockResolvedValue(mockResponse);

      await verifyCloudflareTurnstileToken('token', '127.0.0.1', 'secret-key');
      
      expect(console.log).toHaveBeenCalledWith('Turnstile verification response:', true);
    });

    test('should send correct parameters to Cloudflare API', async () => {
      const mockResponse = { data: { success: true } };
      mockedAxios.post.mockResolvedValue(mockResponse);

      await verifyCloudflareTurnstileToken('test-token', '192.168.1.1', 'test-secret');

      const callArgs = mockedAxios.post.mock.calls[0];
      const urlParams = callArgs[1];
      
      expect(urlParams.get('secret')).toBe('test-secret');
      expect(urlParams.get('response')).toBe('test-token');
      expect(urlParams.get('remoteip')).toBe('192.168.1.1');
    });

    test('should work without remoteIp parameter', async () => {
      const mockResponse = { data: { success: true } };
      mockedAxios.post.mockResolvedValue(mockResponse);

      const result = await verifyCloudflareTurnstileToken('token', undefined, 'secret-key');
      
      expect(result).toBe(true);
      expect(mockedAxios.post).toHaveBeenCalled();
    });
  });
});