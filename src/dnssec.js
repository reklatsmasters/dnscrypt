'use strict';

const { randomFillSync } = require('crypto');
const nacl = require('tweetnacl');
const {
  decode,
  createDecode,
  types: { uint32be, buffer },
} = require('binary-data');
const { padRight, unpadRight } = require('./utils');

module.exports = {
  encrypt,
  parse,
  decrypt,
};

const MIN_QUERY_SIZE = 256;

/**
 * @typedef {Object} EncryptedQuery
 * @property {Buffer} message
 * @property {Buffer} nonce
 * @property {Uint8Array} sharedKey
 */

/**
 * @typedef {Object} EncryptedResponse
 * @property {Object} magic
 * @property {number} magic.high
 * @property {number} magic.low
 * @property {Buffer} nonce
 * @property {Buffer} message
 */

const EncryptedHeader = {
  magic: {
    high: uint32be,
    low: uint32be,
  },
  nonce: buffer(nacl.box.nonceLength), // client (1/2) + server (1/2)
};

/**
 * Encrypt DNS query.
 * @param {Buffer} query DNS query.
 * @param {Certificate} certificate Server certificate.
 * @returns {EncryptedQuery}
 */
function encrypt(query, certificate) {
  const { publicKey, secretKey } = nacl.box.keyPair();

  const nonce = Buffer.alloc(nacl.box.nonceLength);
  randomFillSync(nonce, 0, nacl.box.nonceLength / 2);

  const halfNonce = nonce.slice(0, nacl.box.nonceLength / 2);
  const padded = padRight(query, 64, MIN_QUERY_SIZE);

  const sharedKey = nacl.box.before(certificate.resolverPk, secretKey);
  const encrypted = nacl.box.after(padded, nonce, sharedKey);
  const payload = [certificate.clientMagic, publicKey, halfNonce, encrypted];

  return {
    message: Buffer.concat(payload),
    nonce,
    sharedKey,
  };
}

/**
 * Parse encrypted DNS packet.
 * @param {Buffer} message
 * @returns {EncryptedResponse}
 */
function parse(message) {
  const rstream = createDecode(message);
  const response = decode(rstream, EncryptedHeader);
  const encrypted = rstream.slice();

  response.message = encrypted;
  return response;
}

/**
 * Decrypt DNS message.
 * @param {Buffer} message
 * @param {Buffer} nonce
 * @param {Buffer} sharedKey
 * @returns {Buffer}
 */
function decrypt(message, nonce, sharedKey) {
  const padded = nacl.secretbox.open(message, nonce, sharedKey);
  const bufview = Buffer.from(padded.buffer, padded.byteOffset, padded.byteLength);
  const query = unpadRight(bufview);

  return query;
}
