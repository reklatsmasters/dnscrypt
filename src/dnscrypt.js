'use strict';

const dgram = require('dgram');
const { isIPv4 } = require('net');
const Emitter = require('events');
const rrtypes = require('dns-packet/types');
const { Session } = require('./session');
const Protocol = require('./protocol');

const upper = s => s.toUpperCase();
const lower = s => s.toLowerCase();

/**
 * DNSCrypt client.
 */
module.exports = class DNSCrypt extends Emitter {
  /**
   * @class {DNSCrypt}
   * @param {Object} options
   * @param {string} [options.sdns] Secure DNS resolver config.
   * @param {number} [options.timeout] DNS query timeout.
   */
  constructor(options = {}) {
    super();

    this.session = new Session();

    if (typeof options.sdns === 'string' && options.sdns.startsWith('sdns://')) {
      this.session.setResolver(options.sdns);
    }

    const socketType = isIPv4(this.session.serverAddress) ? 'udp4' : 'udp6';
    this.socket = dgram.createSocket(socketType);

    this.socket.once('close', () => {
      this.emit('close');
    });

    this.session.on('error', error => this.emit('error', error));

    this.session.queue.on('timeout', query =>
      process.nextTick(query.callback, new Error('Timed out'))
    );

    this.protocol = new Protocol(this.session, this.socket);
  }

  /**
   * Close the client.
   */
  close() {
    this.socket.close();
  }

  /**
   * Exclude internal dgram socket from the reference counting.
   * @returns {DNSCrypt}
   */
  unref() {
    this.socket.unref();
    return this;
  }

  /**
   * Add internal dgram socket to the reference counting.
   * @returns {DNSCrypt}
   */
  ref() {
    this.socket.ref();
    return this;
  }

  /**
   * Sets secure config of server to be used when performing DNS resolution.
   * @param {string} sdns Secure DNS resolver config.
   */
  setResolver(sdns) {
    if (typeof sdns === 'string' && sdns.startsWith('sdns://')) {
      this.session.setResolver(sdns);
      this.protocol.forgetCertificate();
    } else {
      throw new TypeError('Invalid argument "sdns"');
    }
  }

  /**
   * Start looking up.
   * @param {string} hostname Hostname to resolve.
   * @param {string} rrtype Resource record type.
   * @param {Function} callback
   */
  lookup(hostname, rrtype, callback) {
    if (this.session.certificate === null) {
      this.session.lookupQueue.push({ hostname, rrtype, callback });
      this.protocol.lookupCertificate();
    } else {
      this.protocol.lookup(hostname, rrtype, callback);
    }
  }

  /**
   * Generic resolve.
   * @param {string} hostname Hostname to resolve.
   * @param {string} rrtype Resource record type.
   * @param {Function} callback
   * @returns {void}
   */
  resolveGeneric(hostname, rrtype, callback) {
    const host = lower(hostname);
    const type = upper(rrtype);

    if (rrtypes.toType(rrtype) === 0) {
      throw new TypeError(`The value "${rrtype}" is invalid for option "rrtype"`);
    }

    this.lookup(host, type, (error, response) => {
      if (error) {
        return callback(error);
      }

      // Check truncated response
      if (response.flag_tc) {
        return callback(new Error('Truncated response'));
      }

      if (response.answers.length === 0) {
        return callback(new Error('No data'));
      }

      /** @type {Object[]} */
      const answers = response.answers.filter(
        answer =>
          upper(answer.type) === type && lower(answer.name) === host && upper(answer.class) === 'IN'
      );

      callback(null, answers);
    });
  }

  /**
   * Resolve IP address.
   * @param {string} hostname
   * @param {string} rrtype
   * @param {Object} [options]
   * @param {Function} callback
   * @returns {void}
   */
  resolveAddress(hostname, rrtype, options, callback) {
    this.resolveGeneric(hostname, rrtype, (error, answers) => {
      if (error) {
        return callback(error);
      }

      let addresses;

      if (options.ttl) {
        addresses = answers.map(answer => ({ address: answer.data, ttl: answer.ttl }));
      } else {
        addresses = answers.map(answer => answer.data);
      }

      callback(null, addresses);
    });
  }

  /**
   * Resolve IPv4 address.
   * @param {string} hostname
   * @param {Object} options
   * @param {Function} callback
   */
  resolve4(hostname, options, callback) {
    this.resolveAddress(hostname, 'A', options, callback);
  }

  /**
   * Resolve IPv6 address.
   * @param {string} hostname
   * @param {Object} options
   * @param {Function} callback
   */
  resolve6(hostname, options, callback) {
    this.resolveAddress(hostname, 'AAAA', options, callback);
  }

  /**
   * Resolve CNAME record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveCname(hostname, callback) {
    this.resolveGeneric(hostname, 'CNAME', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(null, answers.map(answer => answer.data));
    });
  }

  /**
   * Resolve NS record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveNs(hostname, callback) {
    this.resolveGeneric(hostname, 'NS', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(null, answers.map(answer => answer.data));
    });
  }

  /**
   * Resolve PTR record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolvePtr(hostname, callback) {
    this.resolveGeneric(hostname, 'PTR', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(null, answers.map(answer => answer.data));
    });
  }

  /**
   * Resolve MX record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveMx(hostname, callback) {
    this.resolveGeneric(hostname, 'MX', (error, answers) => {
      if (error) {
        return callback(error);
      }

      const mapper = ({ exchange, preference }) => ({
        priority: preference,
        exchange,
      });

      callback(null, answers.map(answer => answer.data).map(mapper));
    });
  }

  /**
   * Resolve NAPTR record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveNaptr(hostname, callback) {
    this.resolveGeneric(hostname, 'NAPTR', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(null, answers.map(answer => answer.data));
    });
  }

  /**
   * Resolve SOA record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSoa(hostname, callback) {
    this.resolveGeneric(hostname, 'SOA', (error, answers) => {
      if (error) {
        return callback(error);
      }

      const mapper = ({ mname, rname, minimum, ...soa }) => ({
        nsname: mname,
        hostmaster: rname,
        ...soa,
        minttl: minimum,
      });

      callback(null, answers.map(answer => answer.data).map(mapper));
    });
  }

  /**
   * Resolve SRV record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSrv(hostname, callback) {
    this.resolveGeneric(hostname, 'SRV', (error, answers) => {
      if (error) {
        return callback(error);
      }

      const mapper = ({ target, ...srv }) => ({ name: target, ...srv });

      callback(null, answers.map(answer => answer.data).map(mapper));
    });
  }

  /**
   * Resolve TXT record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveTxt(hostname, callback) {
    this.resolveGeneric(hostname, 'TXT', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(null, answers.map(answer => [answer.data.toString()]));
    });
  }

  /**
   * Uses the DNS protocol to resolve a hostname into an array of the resource records..
   * @param {string} hostname Hostname to resolve.
   * @param {string} rrtype Resource record type.
   * @param {Function} callback
   * @returns {void}
   */
  resolve(hostname, rrtype, callback) {
    switch (rrtype) {
      case 'A':
        this.resolve4(hostname, callback);
        break;
      case 'AAAA':
        this.resolve6(hostname, callback);
        break;
      case 'CNAME':
        this.resolveCname(hostname, callback);
        break;
      case 'MX':
        this.resolveMx(hostname, callback);
        break;
      case 'NS':
        this.resolveNs(hostname, callback);
        break;
      case 'PTR':
        this.resolvePtr(hostname, callback);
        break;
      case 'SOA':
        this.resolveSoa(hostname, callback);
        break;
      case 'SRV':
        this.resolveSrv(hostname, callback);
        break;
      case 'TXT':
        this.resolveTxt(hostname, callback);
        break;
      default:
        break;
    }

    if (rrtypes.toType(rrtype) === 0) {
      throw new TypeError(`The value "${rrtype}" is invalid for option "rrtype"`);
    }

    this.resolveGeneric(hostname, rrtype, callback);
  }
};
