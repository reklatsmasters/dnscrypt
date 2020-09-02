'use strict';

const isLegalPort = (port) => typeof port === 'number' && port > 0 && port < 0xffff;

/**
 * Calculate padding for the buffer using the multiplier.
 * @param {Buffer} buf
 * @param {number} mul
 * @param {number} min
 * @returns {number}
 */
function padLength(buf, mul, min) {
  const reminder = buf.length % mul;

  if (reminder === 0 && buf.length >= min) {
    return 0;
  }

  if (buf.length < min) {
    return min - buf.length;
  }

  return mul - reminder;
}

/**
 * Add padding to the buffer at the right.
 * @param {Buffer} buf
 * @param {number} mul
 * @param {number} min
 * @returns {Buffer}
 */
function padRight(buf, mul, min) {
  const padding = padLength(buf, mul, min);

  if (padding === 0) {
    return buf;
  }

  const pad = Buffer.alloc(padding);
  pad[0] = 0x80;

  return Buffer.concat([buf, pad]);
}

/**
 * Remove padding fromt the buffer.
 * @param {Buffer} buf
 * @returns {Buffer}
 */
function unpadRight(buf) {
  const i = buf.lastIndexOf(0x80);
  return i === -1 ? buf : buf.slice(0, i);
}

/**
 * Check hostname.
 * @param {string} hostname
 */
function checkHostname(hostname) {
  if (typeof hostname !== 'string') {
    throw new TypeError('Argument "hostname" should be a string');
  }
}

/**
 * Check callback type.
 * @param {Function} callback
 */
function checkCallback(callback) {
  if (typeof callback !== 'function') {
    throw new TypeError('Argument "callback" should be a function');
  }
}

/**
 * Internal class to store a callback
 * associated with the query.
 */
class AsyncQuery {
  /**
   * @class {AsyncQuery}
   * @param {secure.EncryptedQuery} query
   * @param {Function} callback
   */
  constructor(query, callback) {
    this.query = query;
    this.callback = callback;
  }
}

/**
 * Generate a random integer.
 * @param {number} minimum
 * @param {number} maximum
 * @returns {number}
 */
function random(minimum, maximum) {
  if (maximum === undefined) {
    // eslint-disable-next-line no-param-reassign
    maximum = minimum;
    // eslint-disable-next-line no-param-reassign
    minimum = 0;
  }

  if (typeof minimum !== 'number' || typeof maximum !== 'number') {
    throw new TypeError('Expected all arguments to be numbers');
  }

  return Math.floor(Math.random() * (maximum - minimum + 1) + minimum);
}

module.exports = {
  padLength,
  padRight,
  unpadRight,
  checkHostname,
  checkCallback,
  isLegalPort,
  AsyncQuery,
  random,
};
