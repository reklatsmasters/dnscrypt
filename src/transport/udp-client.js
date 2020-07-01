'use strict';

const nanoresource = require('nanoresource/emitter');
const random = require('random-int');
const dns = require('dns-packet');
const UDPSocket = require('./udp-socket');
const { validateCertificate } = require('../certificate');

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
      callback(null);
    });
  }

  /**
   * @private
   * @param {Function} callback
   */
  _close(callback) {
    this.socket.close(() => callback());
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

    const onmessage = data => {
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
    this.socket.write(packet, err => {
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
};
