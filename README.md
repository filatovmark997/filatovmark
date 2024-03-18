# filatovmark

A collection of helper functions for cryptographic operations like password hashing and JWT generation.

## Installation

You can install this module via npm: `npm install filatovmark`


## Usage

```javascript
const crypticHelpers = require('cryptic-helpers');

// Example usage
(async () => {
  try {
    const plaintextPassword = 'myPassword123';
    const hashedPassword = await crypticHelpers.hashPassword(plaintextPassword);
    console.log('Hashed password:', hashedPassword);

    const isMatch = await crypticHelpers.comparePassword(plaintextPassword, hashedPassword);
    console.log('Password match:', isMatch);

    const payload = { userId: '123456' };
    const secretKey = 'mySecretKey';
    const token = crypticHelpers.generateToken(payload, secretKey);
    console.log('Generated JWT:', token);

    const decodedPayload = crypticHelpers.verifyToken(token, secretKey);
    console.log('Decoded payload:', decodedPayload);
  } catch (error) {
    console.error('Error:', error.message);
  }
})();
```


