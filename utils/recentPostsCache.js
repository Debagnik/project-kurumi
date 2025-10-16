const nodeCache = require('node-cache');

const POST_TTL_SECONDS = Math.max(1, parseInt(process.env.POST_CACHE_TTL) || 3600); // default 1 hour TTL

const recentPostCache = new nodeCache({stdTTL: POST_TTL_SECONDS, checkperiod: 60*60 });

function getRecentPostsFromCache() {
  const cached = recentPostCache.get("recentPosts");
  if (!cached){ 
    return null;
  }
  return cached;
}

function setRecentPostsToCache(posts, limit) {
  if (!Array.isArray(posts)) return;
  const limited = posts.slice(0, limit);
  recentPostCache.set("recentPosts", limited, POST_TTL_SECONDS);
}

function invalidateRecentPostsCache() {
  recentPostsCache.del("recentPosts");
}

module.exports = {getRecentPostsFromCache, setRecentPostsToCache, invalidateRecentPostsCache}


