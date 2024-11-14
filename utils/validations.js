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