// User privilege Enum
const PRIVILEGE_LEVELS_ENUM = {
  WEBMASTER : 1,
  MODERATOR : 2,
  WRITER: 3
}
exports.PRIVILEGE_LEVELS_ENUM = PRIVILEGE_LEVELS_ENUM;

// Function to validate a URI
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
 * Checks if the user has webmaster privileges
 * @param {Object} currentUser The user object to check
 * @returns {boolean} True if the user has webmaster privileges
 */
exports.isWebMaster = (currentUser) => {
  if (!currentUser) {
    return false;
  }
  return typeof currentUser.privilege === 'number' && currentUser.privilege === PRIVILEGE_LEVELS_ENUM.WEBMASTER;
};