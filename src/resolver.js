'use strict';

const dnsstamp = require('dnsstamp').DNSStamp;
const DNSCrypt = require('./dnscrypt');
const { checkHostname, checkCallback } = require('./utils');

/**
 * Create promise for async answer.
 * @private
 * @returns {Object}
 */
function setupPromise() {
  let callback;

  const promise = new Promise((resolve, reject) => {
    callback = function promiseCallback(err, res) {
      if (err) {
        reject(err);
      } else {
        resolve(res);
      }
    };
  });

  return { callback, promise };
}

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
   * @returns {void}
   */
  resolve(hostname, rrtype, callback) {
    if (typeof rrtype === 'function') {
      callback = rrtype; // eslint-disable-line no-param-reassign
      rrtype = 'A'; // eslint-disable-line no-param-reassign
    }

    if (typeof rrtype !== 'string') {
      rrtype = 'A'; // eslint-disable-line no-param-reassign
    }

    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolve(hostname, rrtype.toUpperCase(), callback);
    return promise;
  }

  /**
   * Resolve IPv4 address.
   * @param {string} hostname
   * @param {Object} [options]
   * @param {Function} callback
   * @returns {void}
   */
  resolve4(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options; // eslint-disable-line no-param-reassign
      options = { ttl: false }; // eslint-disable-line no-param-reassign
    }

    if (typeof options === 'undefined') {
      options = { ttl: false }; // eslint-disable-line no-param-reassign
    }

    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolve4(hostname, { ttl: !!options.ttl }, callback);
    return promise;
  }

  /**
   * Resolve IPv6 address.
   * @param {string} hostname
   * @param {Object} [options]
   * @param {Function} callback
   * @returns {void}
   */
  resolve6(hostname, options, callback) {
    if (typeof options === 'function') {
      callback = options; // eslint-disable-line no-param-reassign
      options = { ttl: false }; // eslint-disable-line no-param-reassign
    }

    if (typeof options === 'undefined') {
      options = { ttl: false }; // eslint-disable-line no-param-reassign
    }

    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolve6(hostname, { ttl: !!options.ttl }, callback);
    return promise;
  }

  /**
   * Resolve CNAME record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveCname(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveCname(hostname, callback);
    return promise;
  }

  /**
   * Resolve NS record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveNs(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveNs(hostname, callback);
    return promise;
  }

  /**
   * Resolve PTR record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolvePtr(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolvePtr(hostname, callback);
    return promise;
  }

  /**
   * Resolve MX record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveMx(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveMx(hostname, callback);
    return promise;
  }

  /**
   * Resolve SOA record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSoa(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveSoa(hostname, callback);
    return promise;
  }

  /**
   * Resolve SRV record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSrv(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveSrv(hostname, callback);
    return promise;
  }

  /**
   * Resolve TXT record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveTxt(hostname, callback) {
    let promise;

    if (typeof callback !== 'function') {
      // eslint-disable-next-line no-param-reassign
      ({ promise, callback } = setupPromise());
    }

    checkHostname(hostname);
    checkCallback(callback);

    this.#dnscrypt.resolveTxt(hostname, callback);
    return promise;
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
