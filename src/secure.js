'use strict';

const { randomFillSync } = require('crypto');
const nacl = require('tweetnacl');
const {
  decode,
  createDecode,
  types: { uint32be, buffer },
} = require('binary-data');
const { padRight, unpadRight } = require('./utils');

const MIN_QUERY_SIZE = 256;
const SERV_MAGIC_HIGH = 0x7236666e;
const SERV_MAGIC_LOW = 0x76576a38;
const { nonceLength } = nacl.box;
const halfNonceLength = Math.trunc(nonceLength / 2);
const minDNSPacketSize = 12 + 5;
const headerLength = 8 + nonceLength; // magic + nonce
const minResponseLength = headerLength + minDNSPacketSize;

const EncryptedHeader = {
  magic: {
    high: uint32be,
    low: uint32be,
  },
  nonce: buffer(nonceLength), // client (1/2) + server (1/2)
};

/**
 * Internal class to store encrypted queries.
 */
class EncryptedQuery {
  /**
   * @class {EncryptedQuery}
   * @param {Buffer} message Encrypted message.
   * @param {Uint8Array} sharedKey Encryption key.
   * @param {Buffer} nonce Client salt.
   */
  constructor(message, sharedKey, nonce) {
    this.message = message;
    this.sharedKey = sharedKey;
    this.nonce = nonce;
    this.clientNonce = nonce.slice(0, halfNonceLength);
  }
}

/**
 * Internal class to store encrypted answers.
 */
class EncryptedAnswer {
  /**
   * @class {EncryptedAnswer}
   * @param {Buffer} message Encrypted message.
   * @param {Buffer} nonce Server salt.
   */
  constructor(message, nonce) {
    this.message = message;
    this.nonce = nonce;
    this.clientNonce = nonce.slice(0, halfNonceLength);
  }
}

/**
 * Check is incoming message have an enough length.
 * @param {Buffer} data
 * @returns {boolean}
 */
function isEnough(data) {
  return data.length >= minResponseLength;
}

/**
 * Encrypt DNS query.
 * @param {Buffer} query DNS query.
 * @param {Certificate} certificate Server certificate.
 * @returns {EncryptedQuery}
 */
function encrypt(query, certificate) {
  const { publicKey, secretKey } = nacl.box.keyPair();

  const nonce = Buffer.alloc(nonceLength);
  randomFillSync(nonce, 0, halfNonceLength);

  const halfNonce = nonce.slice(0, halfNonceLength);
  const padded = padRight(query, 64, MIN_QUERY_SIZE);

  const sharedKey = nacl.box.before(certificate.resolverPk, secretKey);
  const encrypted = nacl.box.after(padded, nonce, sharedKey);
  const payload = [certificate.clientMagic, publicKey, halfNonce, encrypted];

  return new EncryptedQuery(Buffer.concat(payload), sharedKey, nonce);
}

/**
 * Parse encrypted DNS packet.
 * @param {Buffer} message
 * @returns {EncryptedAnswer}
 */
function parse(message) {
  const rstream = createDecode(message);
  const response = decode(rstream, EncryptedHeader);
  const encrypted = rstream.slice();

  if (response.magic.high !== SERV_MAGIC_HIGH && response.magic.low !== SERV_MAGIC_LOW) {
    throw new Error('Invalid magic header');
  }

  return new EncryptedAnswer(encrypted, response.nonce);
}

/**
 * Decrypt DNS message.
 * @param {EncryptedQuery} query
 * @param {EncryptedAnswer} answer
 * @returns {Buffer}
 */
function decrypt(query, answer) {
  const padded = nacl.secretbox.open(answer.message, answer.nonce, query.sharedKey);
  const bufview = Buffer.from(padded.buffer, padded.byteOffset, padded.byteLength);

  return unpadRight(bufview);
}

module.exports = {
  isEnough,
  encrypt,
  parse,
  decode: parse,
  decrypt,
  EncryptedQuery,
  EncryptedAnswer,
};
