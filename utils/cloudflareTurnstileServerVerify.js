/**\
 * Utility function for Cloudflare Turnstile token verification.
 * Turnstile is Cloudflare's CAPTCHA alternative that helps protect forms from spam and abuse.
 * his function verifies that the token provided by the client is valid by checking with Cloudflare's API.
 */

const axios = require('axios');

async function verifyCloudflareTurnstileToken(token, remoteIp, secretKey) {
    // Validate inputs
    if (!token || !secretKey) {
        console.error('Turnstile verification error: Missing required parameters');
        return false;
    }
    
    try {
        const response = await axios.post('https://challenges.cloudflare.com/turnstile/v0/siteverify',
            new URLSearchParams({
                secret: secretKey,
                response: token,
                remoteip: remoteIp
            }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
        if(!(process.env.NODE_ENV === 'production') && response.data.success === false) {
            console.log('Turnstile verification response:', response.data);
        } else {
            console.log('Turnstile verification response:', response.data.success);
        }

        return response.data.success;
    } catch (error) {
        console.error('Turnstile verification error:', error.message);
        return false;
    }
}

module.exports = verifyCloudflareTurnstileToken;