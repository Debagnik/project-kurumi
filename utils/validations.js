/**
 * @module validation
 * @description
 * Utility functions and constants for validating URIs and user privileges in the system.
 */

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