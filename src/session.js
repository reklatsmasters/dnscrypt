'use strict';

const Emitter = require('events');
const dnsstamp = require('dnsstamp').DNSStamp;
const debug = require('debug')('dnscrypt');
const { TimedQueue } = require('./timed-queue');

// Default is quad9 - no-dnssec, no-log, no-filter resolver.
const DEFAULT_RESOLVER =
  'sdns://AQYAAAAAAAAADTkuOS45LjEwOjg0NDMgZ8hHuMh1jNEgJFVDvnVnRt803x2EwAuMRwNo34Idhj4ZMi5kbnNjcnlwdC1jZXJ0LnF1YWQ5Lm5ldA';

const DEFAULT_TIMEOUT = 2e3;

/**
 * This class implements DNSCrypt session.
 */
class Session extends Emitter {
  /**
   * @class {Session}
   * @param {number} queryTimeout
   */
  constructor(queryTimeout = DEFAULT_TIMEOUT) {
    super();
    this.setResolver(DEFAULT_RESOLVER);

    this.lastDnsId = 0;
    this.connected = false; // Check if socket is support connect / disconnect API.
    this.certificatePacket = null; // Parsed response with server certificate.
    this.certificate = null; // Resolver certificate.
    this.lookupQueue = []; // Queue to wait for certificate before starting looking up.
    this.queue = new TimedQueue(queryTimeout); // Queue of pending queries.
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
  DEFAULT_RESOLVER,
  DEFAULT_TIMEOUT,
};
