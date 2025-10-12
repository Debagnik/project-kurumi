const NodeCache = require('node-cache');
const siteConfig = require('../server/models/config');

// Cache with 5 minute TTL
const configCache = new NodeCache({ stdTTL: 300, checkperiod: 60 });

/**
 * @middleware fetchSiteConfigCached
 * @description Middleware responsible for efficiently retrieving and caching the global site configuration.
 *              It first checks if the configuration is available in the in-memory cache. If not, it queries
 *              the MongoDB database, caches the result, and attaches the configuration to `res.locals.siteConfig`.
 *              This reduces redundant database queries and improves performance across requests.
 * 
 * @dependencies
 * @requires node-cache - Provides lightweight, in-memory caching functionality.
 * @requires ../models/config - Mongoose model for accessing the site configuration document.
 * 
 * @request
 * @param {import('express').Request} req - Express request object.
 * @param {import('express').Response} res - Express response object.
 * @param {import('express').NextFunction} next - Express next middleware function.
 * 
 * @returns {void} Proceeds to the next middleware with `next()` if successful.
 * @returns {500} Renders an error page if configuration retrieval or caching fails.
 * 
 * @example
 * const { fetchSiteConfigCached } = require('./middleware/fetchSiteConfigCached');
 * app.use(fetchSiteConfigCached);
 */
const fetchSiteConfigCached = async (req, res, next) => {
  try {
    let config = configCache.get('siteConfig');

    // Bypass for health check endpoint
    if(req.path === '/healtz'){
      if(process.env.NODE_ENV !== 'production'){
        console.log('Health check endpoint accessed, bypassing site config fetch.');
      }
      return next();
    }
    
    if (!config) {
      const found = await siteConfig.findOne().lean();
      if (!found) {
        console.warn('Site config is not available in database, creating a default one.');
        const defaultConfig = {
          isRegistrationEnabled: true,
          lastModifiedBy: 'System',
          lastModifiedDate: Date.now(),
          isCommentsEnabled: false,
          isCaptchaEnabled: false,
          isAISummerizerEnabled: false
        }
        try{
          const createConfigObject = await new siteConfig(defaultConfig).save();
          config = createConfigObject.toObject();
        } catch(err){
          console.error("Error creating default site config:", err.message);
          throw new Error(`Failed to create default site configuration: ${err.message}`);
        }
      } else {
        config = found;
        if(process.env.NODE_ENV !== 'production'){
          console.log('Site config fetched from database.');
        }
        configCache.set('siteConfig', config);
      }
    } else {
      if(process.env.NODE_ENV !== 'production'){
        console.log('Site config fetched from cache.');
      }
    }
    
    res.locals.siteConfig = config;
    next();
  } catch (error) {
    console.error("Critical: Site Config Cache error", error.message);
    return res.status(500).render('error', {
      locals: {
        title: 'Configuration Error',
        description: 'Unable to load site configuration'
      }
    });
  }
};

/**
 * @function invalidateCache
 * @description Manually invalidates the cached site configuration (`siteConfig` key) from memory.
 *              This function should be called after updating the site configuration in the database,
 *              ensuring that subsequent requests fetch the latest configuration.
 * 
 * @returns {void} Removes the `siteConfig` entry from the in-memory cache.
 * 
 * @example
 * const { invalidateCache } = require('./middleware/fetchSiteConfigCached');
 * invalidateCache(); // Clears the cached configuration
 */
const invalidateCache = () => configCache.del('siteConfig');

/**
 * @function getCacheStatus
 * @description Checks the in-memory site configuration cache (`configCache`) and returns
 *              whether the cached configuration is available or not.
 * 
 * @returns {string} Returns `'available'` if the `siteConfig` key exists in the cache,
 *                   otherwise returns `'unavailable'`.
 */
const getCacheStatus = () => {
  return configCache.has('siteConfig') ? 'available' : 'unavailable';
}

module.exports = { fetchSiteConfigCached, invalidateCache, getCacheStatus };
