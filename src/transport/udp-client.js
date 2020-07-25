'use strict';

const nanoresource = require('nanoresource/emitter');
const random = require('random-int');
const dns = require('dns-packet');
const UDPSocket = require('./udp-socket');
const { validateCertificate } = require('../certificate');
const secure = require('../secure');
const { TimedQueue } = require('../timed-queue');
const { AsyncQuery } = require('../utils');

/**
 * @typedef {Object} UDPClientOptions
 * @property {Session} session Instance of dnscrypt session.
 */

/**
 * DNSCrypt UDP client abstraction.
 */
module.exports = class UDPClient extends nanoresource {
  /**
   * @class {UDPClient}
   * @param {UDPClientOptions} options
   */
  constructor(options) {
    super();

    this.session = options.session;
    this.socket = new UDPSocket({
      port: options.session.serverPort,
      address: options.session.serverAddress,
    });
    this.queue = new TimedQueue(this.session.queryTimeout); // Queue of pending queries.
  }

  /**
   * @private
   * @param {Function} callback
   */
  _open(callback) {
    const packet = {
      id: random(1, 0xffff),
      type: 'query',
      questions: [
        {
          type: 'TXT',
          name: this.session.resolver.providerName,
        },
      ],
    };

    this._certificate(packet, (err, certificate) => {
      if (err) {
        this.socket.close(() => callback(err));
        return;
      }

      this.session.certificate = certificate;
      this._follow();
      callback(null);
    });
  }

  /**
   * @private
   * @param {Function} callback
   */
  _close(callback) {
    this.socket.close(() => {
      this.queue.clear();
      callback();
    });
  }

  /**
   * Query certificate.
   * @param {Object} query DNS query.
   * @param {Function} callback
   * @private
   */
  _certificate(query, callback) {
    if (!this.active(callback)) {
      return;
    }

    const packet = dns.encode(query);
    const timer = setTimeout(() => {
      cleanup(this);
      this.inactive(callback, new Error('ETIMEDOUT'));
    }, this.session.queryTimeout);

    const onmessage = (data) => {
      let response;

      try {
        response = dns.decode(data);
      } catch (_) {
        return;
      }

      if (response.id !== query.id) {
        return;
      }

      let certificate;

      try {
        certificate = validateCertificate(response, this.session.resolver);
      } catch (error) {
        cleanup(this);
        this.inactive(callback, error);
        return;
      }

      cleanup(this);
      this.inactive(callback, null, certificate);
    };

    this.socket.on('data', onmessage);
    this.socket.write(packet, (err) => {
      if (err) {
        cleanup(this);
        return this.inactive(callback, err);
      }
    });

    /**
     * @param {UDPClient} client
     */
    function cleanup(client) {
      clearTimeout(timer);
      client.socket.off('data', onmessage);
    }
  }

  /**
   * Make DNSCrypt query.
   * @param {string} hostname
   * @param {Object} [options]
   * @param {Function} callback
   */
  lookup(hostname, options, callback) {
    if (typeof hostname !== 'string') {
      throw new TypeError('Argument "hostname" must be a String');
    }

    if (typeof callback !== 'function') {
      throw new TypeError('Argument "callback" must be a Function');
    }

    let flags = dns.RECURSION_DESIRED | dns.RECURSION_AVAILABLE;
    let rrtype;

    if (typeof options === 'string') {
      rrtype = options;
    } else if (options != null && typeof options === 'object') {
      if (typeof options.rrtype === 'string') {
        // eslint-disable-next-line prefer-destructuring
        rrtype = options.rrtype;
      }

      if (typeof options.flags === 'number') {
        // eslint-disable-next-line prefer-destructuring
        flags = options.flags;
      }
    }

    const query = dns.encode({
      id: random(1, 0xffff),
      type: 'query',
      flags,
      questions: [
        {
          type: rrtype,
          name: hostname,
        },
      ],
    });

    this.open((err) => {
      if (err) {
        return callback(err);
      }

      if (!this.active(callback)) {
        return;
      }

      this._enqueue(query, (error, response) => {
        if (error) {
          return this.inactive(callback, error);
        }

        try {
          const answer = dns.decode(response);

          return this.inactive(callback, null, answer);
        } catch (error2) {
          return this.inactive(callback, error2);
        }
      });
    });
  }

  /**
   * @private
   * @param {Buffer} query
   * @param {Function} callback
   */
  _enqueue(query, callback) {
    let request;

    try {
      request = secure.encrypt(query, this.session.certificate);
    } catch (error) {
      callback(error);
      return;
    }

    this.socket.write(request.message, (err) => {
      if (err) {
        return callback(err);
      }

      this.queue.push(new AsyncQuery(request, callback));
    });
  }

  /**
   * Start listening for internal events.
   * @private
   */
  _follow() {
    this.queue.on('timeout', (query) => query.callback(new Error('ETIMEDOUT')));
    this.socket.on('data', (data) => {
      if (!secure.isEnough(data)) {
        return;
      }

      let response;

      try {
        response = secure.decode(data);
      } catch (_) {
        return;
      }

      /** @type {AsyncQuery} */
      const box = this.queue.drop(
        (asyncQuery) => Buffer.compare(response.clientNonce, asyncQuery.query.clientNonce) === 0
      );

      if (box == null) {
        return;
      }

      let decrypted;

      try {
        decrypted = secure.decrypt(box.query, response);
      } catch (error) {
        return box.callback(error);
      }

      // TODO: on decryption error we should continue waiting for valid answer.

      box.callback(null, decrypted);
    });
  }
};
