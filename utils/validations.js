exports.isValidURI = (string) => {
    if (!string || string.trim() === '') {
      return false;
    }
    try {
      new URL(string);
      return true;
    } catch (_) {
      console.error("Invalid URI, using default image");
      return false;
    }
  };