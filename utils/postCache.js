/**
 * @file postCache.js
 * @description In-memory cache for blog posts fetched by uniqueId using `node-cache`.
 *              Supports hit-aware LRU eviction, TTL-based auto-pruning, daily hit reset,
 *              configurable max size, and cache invalidation by uniqueId.
 */

const nodeCache = require('node-cache');

const MAX_CACHE_SIZE = parseInt(process.env.POST_CACHE_MAX_SIZE) || 100;
const POST_TTL_SECONDS = parseInt(process.env.POST_CACHE_TTL) || 3600; // default 1 hour TTL
const HIT_RESET_INTERVAL_HOURS = parseInt(process.env.HIT_RESET_INTERVAL_HOURS) || 24;

const cache = new nodeCache({stdTTL: POST_TTL_SECONDS, checkperiod: 60*60 });

/**
 * @function getPostFromCache
 * @description Retrieves post data from cache by uniqueId and increments hit count.
 * 
 * @param {string} uniqueId - Unique identifier of the post
 * @returns {Object|null} Processed post data or null if not in cache
 */
function getPostFromCache(uniqueId){
    const entry = cache.get(uniqueId);
    if(!entry){
        return null;
    }

    entry.hits++;
    cache.set(uniqueId, entry, POST_TTL_SECONDS);
    return entry.data;
}

/**
 * @function setPostToCache
 * @description Saves processed post data to cache. Evicts least-hit item if cache exceeds max size.
 * 
 * @param {string} uniqueId - Unique identifier of the post
 * @param {Object} processedData - Processed post data
 */
function setPostToCache(uniqueId, processedData){
    if(cache.has(uniqueId)){
        const entry = cache.get(uniqueId);
        entry.data = processedData;
        entry.hits++;
        cache.set(uniqueId, entry, POST_TTL_SECONDS);
        return;
    }

    // LRU-Cache management, Evict Least-hit entry when cache is full
    if(cache.keys().length >= MAX_CACHE_SIZE){
        let minHits = Infinity;
        let keyToEvict = null;

        cache.keys().forEach(key => {
            const hits = cache.get(key)?.hits || 0;
            if(hits < minHits){
                minHits = hits;
                keyToEvict = key;
            } 
        });

        if(keyToEvict){
            if(process.env.NODE_ENV === 'production'){
                console.log(`evicting post data with unique id: ${keyToEvict}. from post Cache`);
            }
            cache.del(keyToEvict);
        }
    }

    if(process.env.NODE_ENV === 'production'){
        console.log(`saving post processed data with unique id: ${uniqueId}. to post Cache`);
    }
    cache.set(uniqueId, {data: processedData, hits: 1}, POST_TTL_SECONDS);
}

/**
 * @function invalidateCache
 * @description Deletes a cached post by uniqueId if it exists.
 * 
 * @param {string} uniqueId - Unique identifier of the post
 */
function invalidateCache(uniqueId) {
  if(cache.has(uniqueId)){
    cache.del(uniqueId);
  }
  return;
}

/**
 * @function getCacheSize
 * @description Returns the current number of entries in the cache.
 * 
 * @returns {number} Cache size
 */
function getCacheSize() {
  return {maxCacheSize: process.env.NODE_ENV === 'production' ? 'hidden' : MAX_CACHE_SIZE, cacheSize: cache.keys().length};
}

/**
 * @function resetHitsDaily
 * @description Resets hit counts for all cached entries every 24 hours to implement "least hits daily" eviction.
 */
function resetHitsDaily() {
  cache.keys().forEach(key => {
    const entry = cache.get(key);
    if (entry) {
      entry.hits = 0;
      cache.set(key, entry, POST_TTL_SECONDS);
    }
  });
  console.log(`[Cache] Daily hit counts reset at ${new Date().toISOString()}`);
}

// Schedule daily hit reset
setInterval(resetHitsDaily, HIT_RESET_INTERVAL_HOURS * 60 * 60 * 1000);

module.exports = {
  getPostFromCache,
  setPostToCache,
  invalidateCache,
  getCacheSize
};