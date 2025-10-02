/**
 * @module validation
 * @description
 * Utility functions and constants for validating URIs and user privileges in the system.
 */

const sanitizeHtml = require('sanitize-html');
const {CONSTANTS} = require('./constants')


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
  return typeof currentUser.privilege === 'number' && currentUser.privilege === CONSTANTS.PRIVILEGE_LEVELS_ENUM.WEBMASTER;
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
 *                     placeholder string defined in the `TRACKING_SCRIPT_ERROR_MSG` environment variable.
 *
 * @example
 * const result = isValidTrackingScript(req.body.googleAnalyticsScript);
 * console.log(result); // Valid script or fallback TRACKING_SCRIPT_ERROR_MSG
 */
exports.isValidTrackingScript = (script) => {
  let errorString = process.env.TRACKING_SCRIPT_ERROR_MSG;
  if(!errorString){
    errorString = 'Error on script validation'
    console.warn('Environment Variable TRACKING_SCRIPT_ERROR_MSG that is the default error message for when tracking script fails is not set, please report to Webmaster');
  }

  // Basic validation
  if (typeof script !== 'string' || script.length > 5000) {
    return errorString;
  }

  try {
    // Google Analytics validation: must match regex and contain 'gtag('config')'
    if (CONSTANTS.GA_REGEX.test(script) && script.includes("gtag('config'")) {
      return script;
    }

    // Inspectlet validation
    if (CONSTANTS.INSPECTLET_REGEX.test(script)) {
      return script;
    }

    // Microsoft Clarity validation
    if (CONSTANTS.CLARITY_REGEX.test(script)) {
      return script;
    }

    // None matched
    return errorString;
  } catch (error) {
    console.error('Error validating tracking script:', error);
    return errorString;
  }
};

/**
 * Parses a comma-separated string of tags, sanitizes each tag, 
 * removes disallowed characters, limits their length, and filters out empty tags.
 *
 * @param {string} textTags - A comma-separated string of tags to parse.
 * @returns {string[]} An array of sanitized, trimmed, and filtered tags.
 */
exports.parseTags = (textTags) => {
  if (typeof textTags !== 'string') {
    return [];
  }

  return textTags
    .split(',')
    .map(tag => tag.trim())
    .map(tag =>
      sanitizeHtml(tag, {
        allowedTags: [],
        allowedAttributes: {}
      })
    )
    .map(tag => tag.replace(CONSTANTS.TAGS_REGEX, CONSTANTS.EMPTY_STRING))
    .map(tag => tag.substring(0, 30))
    .filter(tag => tag.length > 0);
}
