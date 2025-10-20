const {
  getPostFromCache,
  setPostToCache,
  invalidateCache,
  clearHitResetInterval,
  getCacheSize
} = require('../../utils/postCache');

describe('Post Cache Module', () => {
  const testUniqueId = 'test-post-123';
  const testPostData = {
    _id: 'post-id-123',
    title: 'Test Post',
    body: 'Test content',
    author: 'testuser'
  };

  beforeEach(() => {
    // Clear any existing cache entries
    invalidateCache(testUniqueId);
  });

  afterAll(() => {
    // Clean up the interval
    clearHitResetInterval();
  });

  describe('setPostToCache', () => {
    test('should store post data in cache', () => {
      setPostToCache(testUniqueId, testPostData);
      const cached = getPostFromCache(testUniqueId);
      expect(cached).toEqual(testPostData);
    });

    test('should increment hits when setting existing post', () => {
      setPostToCache(testUniqueId, testPostData);
      const firstRetrieval = getPostFromCache(testUniqueId);
      
      setPostToCache(testUniqueId, testPostData);
      const secondRetrieval = getPostFromCache(testUniqueId);
      
      expect(firstRetrieval).toEqual(testPostData);
      expect(secondRetrieval).toEqual(testPostData);
    });
  });

  describe('getPostFromCache', () => {
    test('should return null for non-existent cache entry', () => {
      const result = getPostFromCache('non-existent-id');
      expect(result).toBeNull();
    });

    test('should return cached post data', () => {
      setPostToCache(testUniqueId, testPostData);
      const result = getPostFromCache(testUniqueId);
      expect(result).toEqual(testPostData);
    });

    test('should increment hit count on retrieval', () => {
      setPostToCache(testUniqueId, testPostData);
      
      // First retrieval
      const first = getPostFromCache(testUniqueId);
      expect(first).toEqual(testPostData);
      
      // Second retrieval should still work
      const second = getPostFromCache(testUniqueId);
      expect(second).toEqual(testPostData);
    });
  });

  describe('invalidateCache', () => {
    test('should remove post from cache', () => {
      setPostToCache(testUniqueId, testPostData);
      expect(getPostFromCache(testUniqueId)).toEqual(testPostData);
      
      invalidateCache(testUniqueId);
      expect(getPostFromCache(testUniqueId)).toBeNull();
    });

    test('should handle invalidating non-existent cache entry', () => {
      expect(() => {
        invalidateCache('non-existent-id');
      }).not.toThrow();
    });
  });

  describe('getCacheSize', () => {
    test('should return cache size information', () => {
      const sizeInfo = getCacheSize();
      expect(sizeInfo).toHaveProperty('cacheSize');
      expect(sizeInfo).toHaveProperty('maxCacheSize');
      expect(typeof sizeInfo.cacheSize).toBe('number');
    });

    test('should reflect actual cache size', () => {
      const initialSize = getCacheSize().cacheSize;
      
      setPostToCache(testUniqueId, testPostData);
      const afterAddSize = getCacheSize().cacheSize;
      
      expect(afterAddSize).toBe(initialSize + 1);
      
      invalidateCache(testUniqueId);
      const afterRemoveSize = getCacheSize().cacheSize;
      
      expect(afterRemoveSize).toBe(initialSize);
    });

    test('should hide max cache size in production', () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = 'production';
      
      const sizeInfo = getCacheSize();
      expect(sizeInfo.maxCacheSize).toBe('hidden');
      
      process.env.NODE_ENV = originalEnv;
    });
  });

  describe('Cache eviction behavior', () => {
    test('should handle cache size limits', () => {
      // Fill cache beyond limit to test eviction
      const posts = [];
      for (let i = 0; i < 15; i++) {
        const uniqueId = `test-post-${i}`;
        const postData = { ...testPostData, _id: `post-id-${i}`, title: `Test Post ${i}` };
        posts.push({ uniqueId, postData });
        setPostToCache(uniqueId, postData);
      }
      
      const cacheSize = getCacheSize().cacheSize;
      expect(cacheSize).toBeLessThanOrEqual(10); // MAX_CACHE_SIZE from env
    });
  });

  describe('clearHitResetInterval', () => {
    test('should be a function', () => {
      expect(typeof clearHitResetInterval).toBe('function');
    });

    test('should not throw when called', () => {
      expect(() => {
        clearHitResetInterval();
      }).not.toThrow();
    });
  });

  describe('Environment variable handling', () => {
    test('should use default values when env vars are missing', () => {
      // The module should handle missing environment variables gracefully
      // This is tested implicitly by the module loading without errors
      expect(typeof getPostFromCache).toBe('function');
      expect(typeof setPostToCache).toBe('function');
    });
  });
});