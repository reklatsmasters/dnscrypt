'use strict';

const DNSCrypt = require('./dnscrypt');
const { DEFAULT_RESOLVER, DEFAULT_TIMEOUT } = require('./session');
const dns = require('./dns');

const _resolver = Symbol('resolver');

module.exports = {
  createResolver,
};

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
    const dnscrypt = new DNSCrypt(options);

    if (options.unref) {
      dnscrypt.unref();
    }

    this[_resolver] = dnscrypt;
  }

  /**
   * Returns an array of active DNS servers.
   * @returns {DNSStamp[]}
   */
  getServers() {
    /** @type {DNSCrypt} */
    const client = this[_resolver];

    return dns.getServers(client.session.sdns);
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
    resolve: {
      configurable: false,
      enumerable: true,
      value: dns.resolve.bind(resolver[_resolver]),
    },
    resolve4: {
      configurable: false,
      enumerable: true,
      value: dns.resolve4.bind(resolver[_resolver]),
    },
    resolve6: {
      configurable: false,
      enumerable: true,
      value: dns.resolve6.bind(resolver[_resolver]),
    },
    resolveCname: {
      configurable: false,
      enumerable: true,
      value: dns.resolveCname.bind(resolver[_resolver]),
    },
    resolveNs: {
      configurable: false,
      enumerable: true,
      value: dns.resolveNs.bind(resolver[_resolver]),
    },
    resolvePtr: {
      configurable: false,
      enumerable: true,
      value: dns.resolvePtr.bind(resolver[_resolver]),
    },
    resolveMx: {
      configurable: false,
      enumerable: true,
      value: dns.resolveMx.bind(resolver[_resolver]),
    },
    resolveSoa: {
      configurable: false,
      enumerable: true,
      value: dns.resolveSoa.bind(resolver[_resolver]),
    },
    resolveSrv: {
      configurable: false,
      enumerable: true,
      value: dns.resolveSrv.bind(resolver[_resolver]),
    },
    resolveTxt: {
      configurable: false,
      enumerable: true,
      value: dns.resolveTxt.bind(resolver[_resolver]),
    },
  };

  return Object.defineProperties(resolver, props);
}
