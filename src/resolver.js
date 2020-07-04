'use strict';

const dnsstamp = require('dnsstamp').DNSStamp;
const DNSCrypt = require('./dnscrypt');
const { checkHostname, checkCallback } = require('./utils');

/**
 * A public DNS resolver interface.
 */
class Resolver {
  /** @type {DNSCrypt} */
  #dnscrypt;

  /**
   * @class {Resolver}
   * @param {Object} options
   * @param {string} [options.sdns] Secure DNS resolver config.
   * @param {number} [options.timeout] DNS query timeout.
   */
  constructor(options = {}) {
    this.#dnscrypt = new DNSCrypt(options);
  }

  /**
   * Returns an array of active DNS servers.
   * @returns {DNSStamp[]}
   */
  getServers() {
    return [dnsstamp.parse(this.#dnscrypt.session.sdns)];
  }

  /**
   * Close DNSCrypt session.
   */
  close() {
    this.#dnscrypt.close();
  }

  /**
   * Uses the DNS protocol to resolve a hostname into an array of the resource records..
   * @param {string} hostname Hostname to resolve.
   * @param {string} [rrtype] Resource record type.
   * @param {Function} callback
   */
  resolve(hostname, rrtype, callback) {
    if (typeof rrtype === 'function') {
      callback = rrtype; // eslint-disable-line no-param-reassign
      rrtype = 'A'; // eslint-disable-line no-param-reassign
    }

    checkHostname(hostname);
    checkCallback(callback);

    if (typeof rrtype !== 'string') {
      throw new TypeError(`The value "${rrtype}" is invalid for option "rrtype"`);
    }

    this.#dnscrypt.resolve(hostname, rrtype.toUpperCase(), callback);
  }

  /**
   * Resolve IPv4 address.
   * @param {string} hostname
   * @param {Object} [options]
   * @param {Function} callback
   */
  resolve4(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options; // eslint-disable-line no-param-reassign
      options = { ttl: false }; // eslint-disable-line no-param-reassign
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolve4(hostname, { ttl: !!options.ttl }, callback);
  }

  /**
   * Resolve IPv6 address.
   * @param {string} hostname
   * @param {Object} [options]
   * @param {Function} callback
   */
  resolve6(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options; // eslint-disable-line no-param-reassign
      options = { ttl: false }; // eslint-disable-line no-param-reassign
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolve6(hostname, { ttl: !!options.ttl }, callback);
  }

  /**
   * Resolve CNAME record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveCname(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveCname(hostname, callback);
  }

  /**
   * Resolve NS record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveNs(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveNs(hostname, callback);
  }

  /**
   * Resolve PTR record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolvePtr(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolvePtr(hostname, callback);
  }

  /**
   * Resolve MX record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveMx(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveMx(hostname, callback);
  }

  /**
   * Resolve SOA record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSoa(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveSoa(hostname, callback);
  }

  /**
   * Resolve SRV record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSrv(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveSrv(hostname, callback);
  }

  /**
   * Resolve TXT record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveTxt(hostname, callback) {
    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveTxt(hostname, callback);
  }
}

/**
 * Create a new independent resolver for DNS requests.
 * @param {Object} options
 * @param {string} [options.sdns] Secure DNS resolver config.
 * @param {number} [options.timeout] DNS query timeout.
 * @returns {Resolver}
 */
function createResolver(options = {}) {
  return new Resolver(options);
}

module.exports = {
  createResolver,
  Resolver,
};
