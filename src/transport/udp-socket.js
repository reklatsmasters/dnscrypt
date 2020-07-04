'use strict';

const dgram = require('dgram');
const { isIP, isIPv4 } = require('net');
const nanoresource = require('nanoresource/emitter');
const { isLegalPort } = require('../utils');

/**
 * @typedef {Object} UDPSocketOptions
 * @property {number} port Target port.
 * @property {string} address Target IP address.
 * @property {number} [bindPort] Source port.
 */
/**
 * UDP socket abstraction.
 */
module.exports = class UDPSocket extends nanoresource {
  /**
   * @class {UDPSocket}
   * @param {UDPSocketOptions} opts
   */
  constructor(opts = {}) {
    super();

    const { port, address, bindPort } = opts;

    if (!isIP(address)) {
      throw new Error('Invalid ip address');
    }

    if (!isLegalPort(port)) {
      throw new Error('Invalid port');
    }

    this.port = port;
    this.address = address;

    this.bindPort = isLegalPort(bindPort) ? bindPort : 0;
    this.socket = null;
  }

  /**
   * @private
   * @param {Function} callback
   */
  _open(callback) {
    const type = isIPv4(this.address) ? 'udp4' : 'udp6';
    const socket = dgram.createSocket(type);

    this.socket = socket;

    const connectHandler = () => {
      this.socket.removeListener('error', errorHandler);
      this.socket.on('error', (err) => this.emit('error', err));
      this.socket.on('message', (message) => this.emit('data', message));

      callback(null);
    };

    const listeningHandler = () => {
      this.socket.connect(this.port, this.address);
    };

    /**
     * @param {Error} error
     */
    function errorHandler(error) {
      socket.removeListener('connect', connectHandler);
      socket.removeListener('listening', listeningHandler);

      socket.close(() => callback(error));
    }

    this.socket.once('error', errorHandler);
    this.socket.once('listening', listeningHandler);
    this.socket.once('connect', connectHandler);

    try {
      this.socket.bind(this.bindPort);
    } catch (error) {
      errorHandler(error);
    }
  }

  /**
   * @private
   * @param {Function} callback
   */
  _close(callback) {
    this.socket.close(callback);
    this.socket = null;
  }

  /**
   * Send data.
   * @param {Buffer} data Data to send.
   * @param {Function} callback
   */
  write(data, callback) {
    this.open((error) => {
      if (error) {
        return callback(error);
      }

      if (!this.active(callback)) {
        return;
      }

      this.socket.send(data, 0, data.length, (err, bytes) => {
        if (err) {
          return this.inactive(callback, err);
        }

        this.inactive(callback, null, bytes);
      });
    });
  }
};
