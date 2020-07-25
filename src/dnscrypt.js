'use strict';

const Emitter = require('events');
const rrtypes = require('dns-packet/types');
const { Session } = require('./session');
const UDPClient = require('./transport/udp-client');
const TCPClient = require('./transport/tcp-client');

const upper = (s) => s.toUpperCase();
const lower = (s) => s.toLowerCase();

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

    if (typeof options.timeout === 'number' && options.timeout > 0) {
      this.session.queryTimeout = options.timeout;
    }

    if (typeof options.sdns === 'string' && options.sdns.startsWith('sdns://')) {
      this.session.setResolver(options.sdns);
    }

    // Main client.
    this.client = new UDPClient({ session: this.session });
  }

  /**
   * Close clients.
   * @param {Function} [callback]
   */
  close(callback = noop) {
    this.client.close(callback);
  }

  /**
   * Generic resolve.
   * @param {string} hostname Hostname to resolve.
   * @param {string} rrtype Resource record type.
   * @param {boolean} [noFilter]
   * @param {Function} callback
   * @returns {void}
   */
  lookup(hostname, rrtype, noFilter, callback) {
    const host = lower(hostname);
    const type = upper(rrtype);

    if (rrtypes.toType(rrtype) === 0) {
      throw new TypeError(`The value "${rrtype}" is invalid for option "rrtype"`);
    }

    if (typeof noFilter === 'function') {
      // eslint-disable-next-line no-param-reassign
      callback = noFilter;
      // eslint-disable-next-line no-param-reassign
      noFilter = false;
    } else {
      // eslint-disable-next-line no-param-reassign
      noFilter = !!noFilter;
    }

    /**
     * Prepare response to next parsers.
     * @param {Object} reply
     */
    function prepare(reply) {
      if (reply.answers.length === 0) {
        process.nextTick(callback, new Error('No data'));
        return;
      }

      const answers = noFilter ? reply.answers : filterAnswers(reply, type, host);
      process.nextTick(callback, null, answers);
    }

    this.client.lookup(host, type, (error, response) => {
      if (error) {
        return callback(error);
      }

      // Check truncated response and switch to TCP.
      if (response.flag_tc) {
        const tcpclient = new TCPClient({ session: this.session });

        tcpclient.lookup(host, type, (err, res) => {
          tcpclient.close();

          if (err) {
            return process.nextTick(callback, err);
          }

          prepare(res);
        });

        return;
      }

      prepare(response);
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
    if (typeof options === 'function') {
      // eslint-disable-next-line no-param-reassign
      callback = options;
      // eslint-disable-next-line no-param-reassign
      options = { ttl: false };
    }

    this.lookup(hostname, rrtype, (error, answers) => {
      if (error) {
        return callback(error);
      }

      let addresses;

      if (options.ttl) {
        addresses = answers.map((answer) => ({ address: answer.data, ttl: answer.ttl }));
      } else {
        addresses = answers.map((answer) => answer.data);
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
    this.lookup(hostname, 'CNAME', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(
        null,
        answers.map((answer) => answer.data)
      );
    });
  }

  /**
   * Resolve NS record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveNs(hostname, callback) {
    this.lookup(hostname, 'NS', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(
        null,
        answers.map((answer) => answer.data)
      );
    });
  }

  /**
   * Resolve PTR record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolvePtr(hostname, callback) {
    this.lookup(hostname, 'PTR', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(
        null,
        answers.map((answer) => answer.data)
      );
    });
  }

  /**
   * Resolve MX record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveMx(hostname, callback) {
    this.lookup(hostname, 'MX', (error, answers) => {
      if (error) {
        return callback(error);
      }

      const mapper = ({ exchange, preference }) => ({
        priority: preference,
        exchange,
      });

      callback(null, answers.map((answer) => answer.data).map(mapper));
    });
  }

  /**
   * Resolve NAPTR record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveNaptr(hostname, callback) {
    this.lookup(hostname, 'NAPTR', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(
        null,
        answers.map((answer) => answer.data)
      );
    });
  }

  /**
   * Resolve SOA record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSoa(hostname, callback) {
    this.lookup(hostname, 'SOA', (error, answers) => {
      if (error) {
        return callback(error);
      }

      const mapper = ({ mname, rname, minimum, ...soa }) => ({
        nsname: mname,
        hostmaster: rname,
        ...soa,
        minttl: minimum,
      });

      callback(null, answers.map((answer) => answer.data).map(mapper));
    });
  }

  /**
   * Resolve SRV record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveSrv(hostname, callback) {
    this.lookup(hostname, 'SRV', (error, answers) => {
      if (error) {
        return callback(error);
      }

      const mapper = ({ target, ...srv }) => ({ name: target, ...srv });

      callback(null, answers.map((answer) => answer.data).map(mapper));
    });
  }

  /**
   * Resolve TXT record.
   * @param {string} hostname
   * @param {Function} callback
   * @returns {void}
   */
  resolveTxt(hostname, callback) {
    this.lookup(hostname, 'TXT', (error, answers) => {
      if (error) {
        return callback(error);
      }

      callback(
        null,
        answers.map((answer) => [answer.data.toString()])
      );
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
        return;
      case 'AAAA':
        this.resolve6(hostname, callback);
        return;
      case 'CNAME':
        this.resolveCname(hostname, callback);
        return;
      case 'MX':
        this.resolveMx(hostname, callback);
        return;
      case 'NS':
        this.resolveNs(hostname, callback);
        return;
      case 'PTR':
        this.resolvePtr(hostname, callback);
        return;
      case 'SOA':
        this.resolveSoa(hostname, callback);
        return;
      case 'SRV':
        this.resolveSrv(hostname, callback);
        return;
      case 'TXT':
        this.resolveTxt(hostname, callback);
        return;
      default:
        break;
    }

    if (rrtypes.toType(rrtype) === 0) {
      throw new TypeError(`The value "${rrtype}" is invalid for option "rrtype"`);
    }

    this.lookup(hostname, rrtype, true, callback);
  }
};

/**
 * @private
 */
function noop() {}

/**
 * Filter DNS answers.
 * @param {Object} response
 * @param {string} type
 * @param {string} host
 * @returns {Object[]}
 */
function filterAnswers(response, type, host) {
  return response.answers.filter(
    (answer) =>
      upper(answer.type) === type && lower(answer.name) === host && upper(answer.class) === 'IN'
  );
}
