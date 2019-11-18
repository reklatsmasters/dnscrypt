'use strict';

const dnsstamp = require('dnsstamp').DNSStamp;
const { fromCallback } = require('universalify');
const DNSCrypt = require('./dnscrypt');
const { DEFAULT_RESOLVER, DEFAULT_TIMEOUT } = require('./session');

const _resolver = Symbol('resolver');

module.exports = {
  resolve: fromCallback(resolve),
  resolve4: fromCallback(resolve4),
  resolve6: fromCallback(resolve6),
  resolveCname: fromCallback(resolveCname),
  resolveNs: fromCallback(resolveNs),
  resolvePtr: fromCallback(resolvePtr),
  resolveMx: fromCallback(resolveMx),
  resolveSoa: fromCallback(resolveSoa),
  resolveSrv: fromCallback(resolveSrv),
  resolveTxt: fromCallback(resolveTxt),
  getServers,
  createResolver,
};

/**
 * Create wrapper for callback.
 * @param {DNSCrypt} dns
 * @param {Function} callback
 * @returns {Function}
 */
function createCallback(dns, callback) {
  return (error, data) => {
    dns.close();

    if (error) {
      callback(error);
    } else {
      callback(null, data);
    }
  };
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
 * Check hostname.
 * @param {string} hostname
 */
function checkHostname(hostname) {
  if (typeof hostname !== 'string') {
    throw new TypeError('Argument "hostname" should be a string');
  }
}

/**
 * Resolve IPv4 address.
 * @param {string} hostname
 * @param {Object} [options]
 * @param {Function} callback
 */
function resolve4(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options; // eslint-disable-line no-param-reassign
    options = { ttl: false }; // eslint-disable-line no-param-reassign
  }

  checkHostname(hostname);
  checkCallback(callback);

  const ttl = !!options.ttl || false;
  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolve4(hostname, { ttl }, cb);
}

/**
 * Resolve IPv6 address.
 * @param {string} hostname
 * @param {Object} [options]
 * @param {Function} callback
 */
function resolve6(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options; // eslint-disable-line no-param-reassign
    options = { ttl: false }; // eslint-disable-line no-param-reassign
  }

  checkHostname(hostname);
  checkCallback(callback);

  const ttl = !!options.ttl || false;
  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolve6(hostname, { ttl }, cb);
}

/**
 * Resolve CNAME record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolveCname(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolveCname(hostname, cb);
}

/**
 * Resolve NS record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolveNs(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolveNs(hostname, cb);
}

/**
 * Resolve PTR record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolvePtr(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolvePtr(hostname, cb);
}

/**
 * Resolve MX record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolveMx(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolveMx(hostname, cb);
}

/**
 * Resolve SOA record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolveSoa(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolveSoa(hostname, cb);
}

/**
 * Resolve SRV record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolveSrv(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolveSrv(hostname, cb);
}

/**
 * Resolve TXT record.
 * @param {string} hostname
 * @param {Function} callback
 * @returns {void}
 */
function resolveTxt(hostname, callback) {
  checkHostname(hostname);
  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolveTxt(hostname, cb);
}

/**
 * Uses the DNS protocol to resolve a hostname into an array of the resource records..
 * @param {string} hostname Hostname to resolve.
 * @param {string} [rrtype] Resource record type.
 * @param {Function} callback
 * @returns {void}
 */
function resolve(hostname, rrtype, callback) {
  if (typeof rrtype === 'function') {
    callback = rrtype; // eslint-disable-line no-param-reassign
    rrtype = 'A'; // eslint-disable-line no-param-reassign
  }

  checkHostname(hostname);

  if (typeof rrtype !== 'string') {
    throw new TypeError(`The value "${rrtype}" is invalid for option "rrtype"`);
  }

  checkCallback(callback);

  const dns = this instanceof DNSCrypt ? this : new DNSCrypt();
  const cb = createCallback(dns, callback);

  dns.once('error', cb);
  dns.resolve(hostname, rrtype.toUpperCase(), cb);
}

/**
 * Returns an array of active DNS servers.
 * @returns {DNSStamp[]}
 */
function getServers() {
  return [dnsstamp.parse(DEFAULT_RESOLVER)];
}

/**
 * An independent resolver for DNS requests.
 */
class Resolver {
  /**
   * @class {Resolver}
   * @param {Object} options
   * @param {string} [options.sdns] Secure DNS resolver config.
   * @param {number} [options.timeout] DNS query timeout.
   * @param {boolean} [options.unref] Call `unref` on internal socket.
   */
  constructor(options) {
    const dns = new DNSCrypt(options);

    if (options.unref) {
      dns.unref();
    }

    this[_resolver] = dns;
  }

  /**
   * Returns an array of active DNS servers.
   * @returns {DNSStamp[]}
   */
  getServers() {
    /** @type {DNSCrypt} */
    const client = this[_resolver];

    return getServers(client.session.sdns);
  }

  /**
   * Sets secure config of server to be used when performing DNS resolution.
   * @param {string} sdns Secure DNS resolver config.
   */
  setServers(sdns) {
    /** @type {DNSCrypt} */
    const client = this[_resolver];

    client.setResolver(sdns);
  }
}

/**
 * Create a new independent resolver for DNS requests.
 * @param {Object} options
 * @param {string} [options.sdns] Secure DNS resolver config.
 * @param {number} [options.timeout] DNS query timeout.
 * @param {boolean} [options.unref] Call `unref` on internal socket.
 * @returns {Resolver}
 */
function createResolver(options) {
  let unref = false;
  let sdns = DEFAULT_RESOLVER;
  let timeout = DEFAULT_TIMEOUT;

  if (typeof options.unref === 'boolean') {
    unref = options.unref; // eslint-disable-line prefer-destructuring
  }

  if (typeof options.sdns === 'string') {
    sdns = options.sdns; // eslint-disable-line prefer-destructuring
  }

  if (typeof options.timeout === 'number' && options.timeout > 0) {
    timeout = options.timeout; // eslint-disable-line prefer-destructuring
  }

  const resolver = new Resolver({ unref, sdns, timeout });

  const props = {
    resolve: { configurable: false, enumerable: true, value: resolve.bind(resolver[_resolver]) },
    resolve4: { configurable: false, enumerable: true, value: resolve4.bind(resolver[_resolver]) },
    resolve6: { configurable: false, enumerable: true, value: resolve6.bind(resolver[_resolver]) },
    resolveCname: {
      configurable: false,
      enumerable: true,
      value: resolveCname.bind(resolver[_resolver]),
    },
    resolveNs: {
      configurable: false,
      enumerable: true,
      value: resolveNs.bind(resolver[_resolver]),
    },
    resolvePtr: {
      configurable: false,
      enumerable: true,
      value: resolvePtr.bind(resolver[_resolver]),
    },
    resolveMx: {
      configurable: false,
      enumerable: true,
      value: resolveMx.bind(resolver[_resolver]),
    },
    resolveSoa: {
      configurable: false,
      enumerable: true,
      value: resolveSoa.bind(resolver[_resolver]),
    },
    resolveSrv: {
      configurable: false,
      enumerable: true,
      value: resolveSrv.bind(resolver[_resolver]),
    },
    resolveTxt: {
      configurable: false,
      enumerable: true,
      value: resolveTxt.bind(resolver[_resolver]),
    },
  };

  return Object.defineProperties(resolver, props);
}
