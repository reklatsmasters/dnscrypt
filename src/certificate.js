'use strict';

const nacl = require('tweetnacl');
const {
  decode,
  types: { uint32be, uint16be, buffer },
} = require('binary-data');
const debug = require('debug')('dnscrypt');

module.exports = {
  validate,
  parse,
  validateCertificate,
};

const CERT_MAGIC = 0x444e5343;

const EncodedCertificate = {
  certMagic: uint32be,
  esVersion: uint16be,
  minProtocol: uint16be,
  signature: buffer(64),
  resolverPk: buffer(32),
  clientMagic: buffer(8),
  serial: uint32be,
  ts: {
    start: uint32be,
    end: uint32be,
  },
};

/**
 * @typedef {Object} Certificate
 * @property {number} certMagic Certificate magic number <0x44 0x4e 0x53 0x43>.
 * @property {number} esVersion A cryptographic construction to use with the certificate.
 * @property {number} minProtocol Minimal supported version of DNSCrypt protocol.
 * @property {Buffer} signature 64-byte signature using the Ed25519 algorithm and the provider secret key.
 * @property {Buffer} resolverPk The resolver short-term public key.
 * @property {Buffer} clientMagic The first 8 bytes of a client query.
 * @property {number} serial  4 byte serial number.
 * @property {Object} ts
 * @property {number} ts.start The date the certificate is valid from.
 * @property {number} ts.end The date the certificate is valid until (inclusive).
 */

/**
 * Validate certificate.
 * @param {Certificate} certificate Parsed certificate.
 * @param {Buffer} signed Signed message.
 * @param {Buffer} publicKey Resolver public key.
 * @returns {boolean}
 */
function validate(certificate, signed, publicKey) {
  if (certificate.certMagic !== CERT_MAGIC) {
    return false;
  }

  if (certificate.minProtocol !== 0) {
    return false;
  }

  // We are support only X25519-XSalsa20Poly1305 due to tweetnacl limitation.
  if (certificate.esVersion !== 1) {
    return false;
  }

  if (Buffer.compare(certificate.clientMagic, certificate.resolverPk.slice(0, 8)) !== 0) {
    return false;
  }

  const tsnow = (Date.now() / 1e3) >>> 0;

  if (!(certificate.ts.start <= tsnow && certificate.ts.end >= tsnow)) {
    return false;
  }

  // Check Ed25519 signature.
  if (!nacl.sign.detached.verify(signed, certificate.signature, publicKey)) {
    return false;
  }

  return true;
}

/**
 * Parse certificate.
 * @param {Buffer} encodedCertificate
 * @returns {Certificate}
 */
function parse(encodedCertificate) {
  if (!Buffer.isBuffer(encodedCertificate)) {
    return null;
  }

  try {
    /** @type {Certificate} */
    const certificate = decode(encodedCertificate, EncodedCertificate);

    return certificate;
  } catch (error) {
    debug('invalid certificate', error);
    return null;
  }
}

/**
 * Handle remote certificate.
 * @param {Object} response DNS response.
 * @param {Object} resolver DNSCrypt server config.
 * @returns {Certificate}
 */
function validateCertificate(response, resolver) {
  if (response.type !== 'response') {
    throw new Error('Invalid DNS response');
  }

  if (response.rcode !== 'NOERROR') {
    throw new Error('Invalid DNS response');
  }

  if (response.answers.length < response.questions.length) {
    throw new Error('Invalid DNS response');
  }

  const record = response.answers.find(
    answer => answer.type === 'TXT' && answer.name === resolver.providerName
  );

  if (!record) {
    throw new Error('Invalid DNS response');
  }

  /** @type {Buffer[]} */
  const encodedCertificates = Array.isArray(record.data) ? record.data : [record.data];

  if (encodedCertificates.length === 0) {
    throw new Error('Invalid DNS response');
  }

  // Resolver public key.
  const publicKey = Buffer.from(resolver.pk, 'hex');

  const reducer = (previous, { certificate }) => {
    if (!previous) {
      return certificate;
    }

    return certificate.serial > previous.serial ? certificate : previous;
  };

  const mapper = bytes => {
    const certificate = parse(bytes);

    if (certificate === null) {
      return null;
    }

    const signed = bytes.slice(4 + 2 + 2 + 64);

    return {
      certificate,
      signed,
    };
  };

  const remoteCertificate = encodedCertificates
    .map(bytes => mapper(bytes))
    .filter(Boolean)
    .filter(({ certificate, signed }) => validate(certificate, signed, publicKey))
    .reduce(reducer, null);

  if (remoteCertificate === null) {
    throw new Error('No valid certificates');
  }

  debug('got certificate', remoteCertificate);

  return remoteCertificate;
}
