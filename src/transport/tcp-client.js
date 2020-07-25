'use strict';

const nanoresource = require('nanoresource/emitter');
const random = require('random-int');
const dns = require('dns-packet');
const BufferList = require('../binary/buffer-list');
const TCPSocket = require('./tcp-socket');
const { AsyncQuery } = require('../utils');
const secure = require('../secure');
const { TimedQueue } = require('../timed-queue');

/**
 * @typedef {Object} TCPClientOptions
 * @property {Session} session Instance of dnscrypt session.
 */

/**
 * After having received a response from the resolver, the client and the
 * resolver must close the TCP connection. Multiple transactions over the
 * same TCP connections are not allowed by this revision of the protocol.
 */

/**
 * DNSCrypt TCP client abstraction.
 */
module.exports = class TCPClient extends nanoresource {
  /**
   * @class {TCPClient}
   * @param {TCPClientOptions} options
   */
  constructor(options = {}) {
    super();

    this.session = options.session;
    this.socket = new TCPSocket({
      port: options.session.serverPort,
      address: options.session.serverAddress,
    });
    this.chunks = new BufferList();
    this.queue = new TimedQueue(this.session.queryTimeout)
  }

  /**
   * @private
   * @param {Function} callback
   */
  _close(callback) {
    this.socket.close(callback);
  }

  /**
   * @private
   * @param {Function} callback
   */
  _open(callback) {
    // Certificate got by UDP.
    if (this.session.certificate == null) {
      callback(new Error('Missing certificate'));
      return;
    }

    this.socket.open((err) => {
      if (err) {
        callback(err);
        return;
      }

      this._follow();
      callback(null);
    });
  }

  /**
   * Start listening for internal events.
   * @private
   */
  _follow() {
    this.queue.on('timeout', (query) => query.callback(new Error('ETIMEDOUT')));

    this.socket.on('data', (data) => {
      this.chunks.append(data);

      if (this.chunks.length < 2) {
        return;
      }

      const size = this.chunks.readUInt16BE(0);

      if (this.chunks.length < size + 2) {
        return;
      }

      const packet = this.chunks.slice(2);
      this.emit('encryptedPacket', packet)
    });

    this.on('encryptedPacket', (encryptedPacket) => {
      let response;

      try {
        response = secure.decode(encryptedPacket);
      } catch (_) {
        console.error('decrypt error', _);
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
      request = secure.encrypt(query, this.session.certificate, secure.PROTOCOL_TCP);
    } catch (error) {
      callback(error);
      return;
    }

    const chunk = Buffer.allocUnsafe(request.message.length + 2);
    chunk.writeUInt16BE(request.message.length, 0);
    request.message.copy(chunk, 2);

    this.socket.write(chunk, (err) => {
      if (err) {
        return callback(err);
      }

      this.queue.push(new AsyncQuery(request, callback));
    });
  }
};
