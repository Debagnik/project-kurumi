/**
 * @module validation
 * @description
 * Utility functions and constants for validating URIs and user privileges in the system.
 */

// Regular expression patterns for tracking scripts issue #87
const GA_REGEX = /<script.*src="https:\/\/www\.googletagmanager\.com\/gtag\/js\?id=G-[A-Z0-9]+".*<\/script>/;
const INSPECTLET_REGEX = /window\.__insp\s*=\s*window\.__insp\s*\|\|\s*\[\];.*inspectlet\.js\?wid=\d+/s;
const CLARITY_REGEX = /<script[^>]*>\s*\(function\([^)]*\)\{[\s\S]*?["']https:\/\/www\.clarity\.ms\/tag\/["']\s*\+\s*[a-zA-Z0-9]+[\s\S]*?\}\)\([^)]*\);\s*<\/script>/s;

/**
 * Enum for privilege levels used to determine user roles.
 * @readonly
 * @enum {number}
 * @property {number} WEBMASTER - Full administrative privileges (level 1)
 * @property {number} MODERATOR - Moderation privileges (level 2)
 * @property {number} WRITER - Can write and submit content (level 3)
 */
const PRIVILEGE_LEVELS_ENUM = {
  WEBMASTER : 1,
  MODERATOR : 2,
  WRITER: 3
}
exports.PRIVILEGE_LEVELS_ENUM = PRIVILEGE_LEVELS_ENUM;

/**
 * Validates a given URI string to ensure it's well-formed and safe.
 * Disallows unsafe schemes (like `javascript:`) and common attack patterns.
 *
 * @function
 * @param {string} string - The URI string to validate.
 * @returns {boolean} True if the URI is valid and safe; false otherwise.
 */
exports.isValidURI = (string) => {
  if (!string || string.trim() === '') {
    return false;
  }
  try {
    const url = new URL(string);
    const allowedSchemes = ['http:', 'https:'];
    if (!allowedSchemes.includes(url.protocol)) {
      throw new Error(`Scheme ${url.protocol} not allowed`);
    }
    // Check for common attack patterns
    const suspicious = /[<>'";\(\)]|javascript:|data:|vbscript:/i;
    if (suspicious.test(string)) {
      throw new Error('Suspicious URL pattern detected');
    }
    // Validate hostname
    if (!url.hostname || url.hostname.length < 1) {
      throw new Error('Invalid hostname');
    }
    return true;
  } catch (_) {
    console.error(`Invalid or unsafe URI: "${string.substring(0, 100)}"`);
    return false;
  }
};


/**
 * Checks if the given user has webmaster privileges.
 *
 * @function
 * @param {Object} currentUser - The user object to check.
 * @param {number} currentUser.privilege - The numeric privilege level of the user.
 * @returns {boolean} True if the user has webmaster privileges; false otherwise.
 */
exports.isWebMaster = (currentUser) => {
  if (!currentUser) {
    return false;
  }
  return typeof currentUser.privilege === 'number' && currentUser.privilege === PRIVILEGE_LEVELS_ENUM.WEBMASTER;
};

/**
 * Validates whether a given script string matches one of the known safe tracking scripts.
 *
 * Supported tracking scripts:
 * - Google Analytics (GA4)
 * - Inspectlet
 * - Microsoft Clarity
 *
 * This function uses strict regular expressions and structure checks to validate known
 * safe script patterns, preventing injection of arbitrary or malicious scripts.
 *
 * @param {string} script - The script content to validate.
 * @returns {string} - Returns the original script if it's valid. Otherwise, returns a dummy
 *                     placeholder string defined in the `DUMMY_STRING` environment variable.
 *
 * @example
 * const result = isValidTrackingScript(req.body.googleAnalyticsScript);
 * console.log(result); // Valid script or fallback dummy string
 */
exports.isValidTrackingScript = (script) => {
  const dummyString = process.env.DUMMY_STRING;
  if(!dummyString){
    dummyString = 'Error on script validation'
    console.warn('Environment Variable DUMMY_STRING that is the default error message for when tracking script fails is not set, please report to Webmaster');
  }

  // Basic validation
  if (typeof script !== 'string' || script.length > 5000) {
    return dummyString;
  }

  try {
    // Google Analytics validation: must match regex and contain 'gtag('config')'
    if (GA_REGEX.test(script) && script.includes("gtag('config'")) {
      return script;
    }

    // Inspectlet validation
    if (INSPECTLET_REGEX.test(script)) {
      return script;
    }

    // Microsoft Clarity validation
    if (CLARITY_REGEX.test(script)) {
      return script;
    }

    // None matched
    return dummyString;
  } catch (error) {
    console.error('Error validating tracking script:', error);
    return dummyString;
  }
};
