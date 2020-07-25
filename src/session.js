'use strict';

const Emitter = require('events');
const dnsstamp = require('dnsstamp').DNSStamp;
const debug = require('debug')('dnscrypt');

const { DNSCRYPT_RESOLVER } = process.env;

// Default is quad9 - no-dnssec, no-log, no-filter resolver.
const DEFAULT_RESOLVER =
  'sdns://AQYAAAAAAAAADTkuOS45LjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA';
let MAIN_RESOLVER = DEFAULT_RESOLVER;

const DEFAULT_TIMEOUT = 2e3;

// Set up resolver from env.
if (typeof DNSCRYPT_RESOLVER === 'string') {
  try {
    dnsstamp.parse(DNSCRYPT_RESOLVER);
    MAIN_RESOLVER = DNSCRYPT_RESOLVER;
    debug('set up resolver from env');
  } catch (err) {
    debug('unable to parse DNSCRYPT_RESOLVER env', err);
  }
}

/**
 * This class implements DNSCrypt session.
 */
class Session extends Emitter {
  /**
   * @class {Session}
   */
  constructor() {
    super();
    this.setResolver(MAIN_RESOLVER);

    this.certificate = null; // Resolver certificate.
    this.certificateTimeout = DEFAULT_TIMEOUT;
    this.queryTimeout = DEFAULT_TIMEOUT;
  }

  /**
   * Set sdns resolver.
   * @param {string} sdns Base64 string.
   */
  setResolver(sdns) {
    this.sdns = sdns;
    this.resolver = dnsstamp.parse(sdns);

    const [address, port] = this.resolver.addr.split(':');
    this.serverAddress = address;
    this.serverPort = Number(port);

    debug('use resolver', this.resolver);
  }
}

module.exports = {
  Session,
  DEFAULT_RESOLVER: MAIN_RESOLVER,
  DEFAULT_TIMEOUT,
};
