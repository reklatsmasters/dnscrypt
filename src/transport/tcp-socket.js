'use strict';

const net = require('net');
const nanoresource = require('nanoresource/emitter');
const { isLegalPort } = require('../utils');

/**
 * @typedef {Object} TCPSocketOptions
 * @property {number} port Target port.
 * @property {string} address Target IP address.
 */

/**
 * TCP socket abstraction.
 */
module.exports = class TCPSocket extends nanoresource {
  /**
   * @class {TCPSocket}
   * @param {TCPSocketOptions} options
   */
  constructor(options = {}) {
    super();

    const { port, address } = options;

    if (!net.isIP(address)) {
      throw new Error('Invalid ip address');
    }

    if (!isLegalPort(port)) {
      throw new Error('Invalid port');
    }

    this.port = port;
    this.address = address;
    this.socket = null;
  }

  /**
   * @private
   * @param {Function} callback
   */
  _open(callback) {
    const socket = net.connect(this.port, this.address, connectHandler);
    this.socket = socket;

    const self = this;

    /**
     * @param {Error} error
     */
    function errorHandler(error) {
      socket.off('connection', connectHandler);
      callback(error);
    }

    /**
     * @param {Error} error
     */
    function connectHandler() {
      socket.off('error', errorHandler);

      socket.on('data', (data) => self.emit('data', data));
      socket.on('error', (error) => self.emit('error', error));

      callback(null);
    }
  }

  /**
   * @private
   * @param {Function} callback
   */
  _close(callback) {
    this.socket.end(callback);
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

      this.socket.write(data, (err) => {
        if (err) {
          return this.inactive(callback, err);
        }

        this.inactive(callback, null);
      });
    });
  }
};
