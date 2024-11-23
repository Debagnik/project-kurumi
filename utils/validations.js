// User privilege Enum
const PRIVILEGE_LEVELS_ENUM = {
  WEBMASTER : 1,
  MODERATOR : 2,
  WRITER: 3
}

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