'use strict';

module.exports = {
  padLength,
  padRight,
  unpadRight,
};

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
