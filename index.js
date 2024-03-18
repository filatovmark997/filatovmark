const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

/**
 * Function to hash a plaintext password using bcrypt
 * @param {string} password - Plain text password
 * @returns {Promise<string>} - Resolves to hashed password
 */
async function hashPassword(password) {
  const saltRounds = 10;
  return bcrypt.hash(password, saltRounds);
}

/**
 * Function to compare a plaintext password with its hashed version
 * @param {string} password - Plain text password
 * @param {string} hashedPassword - Hashed password
 * @returns {Promise<boolean>} - Resolves to true if passwords match, false otherwise
 */
async function comparePassword(password, hashedPassword) {
  return bcrypt.compare(password, hashedPassword);
}

/**
 * Function to generate a JSON Web Token (JWT) with a given payload
 * @param {Object} payload - Payload to be encoded in the JWT
 * @param {string} secretKey - Secret key to sign the JWT
 * @param {Object} options - Additional options for jwt.sign
 * @returns {string} - JWT
 */
function generateToken(payload, secretKey, options = {}) {
  return jwt.sign(payload, secretKey, options);
}

/**
 * Function to verify and decode a JSON Web Token (JWT)
 * @param {string} token - JWT to be verified and decoded
 * @param {string} secretKey - Secret key used to sign the JWT
 * @returns {Object} - Decoded payload
 */
function verifyToken(token, secretKey) {
  return jwt.verify(token, secretKey);
}

module.exports = {
  hashPassword,
  comparePassword,
  generateToken,
  verifyToken
};
