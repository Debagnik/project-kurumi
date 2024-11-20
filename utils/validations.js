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
    return true;
  } catch (_) {
    console.error(`Invalid or unsafe URI: "${string}"`);
    return false;
  }
};

const WEBMASTER_PRIVILEGE_LEVEL = 1;
/**
 * Checks if the user has webmaster privileges
 * @param {Object} currentUser The user object to check
 * @returns {boolean} True if the user has webmaster privileges
 */
exports.isWebMaster = (currentUser) => {
  if (!currentUser) {
    return false;
  }
  return typeof currentUser.privilege === 'number' && currentUser.privilege === WEBMASTER_PRIVILEGE_LEVEL;
};