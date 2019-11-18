'use strict';

const Emitter = require('events');
const packet = require('dns-packet');
const random = require('random-int');
const debug = require('debug')('dnscrypt');
const nacl = require('tweetnacl');
const { createMachine, createState } = require('next-state');
const cert = require('./certificate');
const dnssec = require('./dnssec');

// INIT -> REQUEST_CERTIFICATE -> CERTIFICATE -> READY
//  ^---------------------------------------------|

const DNSC_INIT = 'DNSC_INIT'; // init state
const DNSC_REQUEST_CERTIFICATE = 'DNSC_REQUEST_CERTIFICATE';
const DNSC_CERTIFICATE = 'DNSC_CERTIFICATE'; // wait for certificate
const DNSC_READY = 'DNSC_READY'; // ready for encrypted query

const transitions = {
  [DNSC_INIT]: createState(DNSC_REQUEST_CERTIFICATE, DNSC_READY),
  [DNSC_REQUEST_CERTIFICATE]: createState(DNSC_CERTIFICATE),
  [DNSC_CERTIFICATE]: createState(DNSC_READY),
};

const SERV_MAGIC_HIGH = 0x7236666e;
const SERV_MAGIC_LOW = 0x76576a38;
const minDNSPacketSize = 12 + 5;
const headerLength = 8 + nacl.box.nonceLength;
const minResponseLength = headerLength + minDNSPacketSize;

/**
 * Storage for pending query state.
 */
class AsyncQuery {
  /**
   * @class {AsyncQuery}
   * @param {Buffer} nonce
   * @param {Buffer} sharedKey
   * @param {Function} callback
   */
  constructor(nonce, sharedKey, callback) {
    this.nonce = nonce;
    this.sharedKey = sharedKey;
    this.callback = callback;
  }
}

/**
 * DNSCrypt protocol.
 */
module.exports = class Protocol extends Emitter {
  /**
   * @class {Protocol}
   * @param {Session} session DNSCrypt session.
   * @param {dgram.Socket} socket UDP socket.
   */
  constructor(session, socket) {
    super();

    this.session = session;
    this.socket = socket;
    this.machine = createMachine(transitions, DNSC_INIT);

    this.machine.on(DNSC_CERTIFICATE, () => onCertificate(this.machine, session));
    this.machine.on(DNSC_READY, () => this.lookupQueue());

    socket.on('message', (message, rinfo) => this.onmessage(message, rinfo));
  }

  /**
   * Reset certificate state to default.
   */
  forgetCertificate() {
    this.session.certificate = null;

    if (this.machine.state !== DNSC_INIT) {
      this.machine.next(DNSC_INIT);
    }
  }

  /**
   * Request remote certificate.
   * @returns {void}
   */
  lookupCertificate() {
    if (this.machine.state === DNSC_REQUEST_CERTIFICATE) {
      debug('looking up certificate already on fly');
      return;
    }

    this.machine.next(DNSC_REQUEST_CERTIFICATE);
    this.session.lastDnsId = random(1, 0xffff);

    const query = packet.encode({
      id: this.session.lastDnsId,
      type: 'query',
      questions: [
        {
          type: 'TXT',
          name: this.session.resolver.providerName,
        },
      ],
    });

    debug('get certificate, id=%s', this.session.lastDnsId);

    this.write(query, error => {
      if (error) {
        process.nextTick(() => this.session.emit('error', error));
      }
    });
  }

  /**
   * Lookup DNS queued queries.
   */
  lookupQueue() {
    if (this.machine.state !== DNSC_READY) {
      throw new Error('Missing certificate');
    }

    const lookups = this.session.lookupQueue.slice();
    this.session.lookupQueue.length = 0;

    if (lookups.length === 0) {
      debug('no requests');
      return;
    }

    lookups.forEach(({ hostname, rrtype, callback }) => this.lookup(hostname, rrtype, callback));
  }

  /**
   * @private
   * @param {Buffer} message
   * @param {RemoteInfo} rinfo
   */
  onmessage(message, rinfo) {
    if (!this.session.connected) {
      if (!isValidSender(rinfo, this.session)) {
        return;
      }
    }

    switch (this.machine.state) {
      case DNSC_REQUEST_CERTIFICATE:
        this.oncertificate(message);
        break;
      case DNSC_READY:
        this.onresponse(message);
        break;
      default:
        debug('invalid state %s', this.machine.state);
        break;
    }
  }

  /**
   * Check request ID before handle certificate.
   * @param {Buffer} message
   * @returns {void}
   */
  oncertificate(message) {
    if (this.machine.state !== DNSC_REQUEST_CERTIFICATE) {
      return;
    }

    const response = packet.decode(message);

    if (response.id !== this.session.lastDnsId) {
      return;
    }

    this.session.certificatePacket = response;

    try {
      this.machine.next(DNSC_CERTIFICATE);
    } catch (error) {
      process.nextTick(() => this.session.emit('error', error));
    } finally {
      this.session.certificatePacket = null;
    }
  }

  /**
   * Lookup single DNS query.
   * @param {string} hostname
   * @param {string} rrtype
   * @param {Function} callback
   * @returns {void}
   */
  lookup(hostname, rrtype, callback) {
    if (this.machine.state !== DNSC_READY) {
      throw new Error('Missing certificate');
    }

    const query = packet.encode({
      id: random(1, 0xffff),
      type: 'query',
      flags: packet.RECURSION_DESIRED | packet.RECURSION_AVAILABLE,
      questions: [
        {
          type: rrtype,
          name: hostname,
        },
      ],
    });

    const encrypted = dnssec.encrypt(query, this.session.certificate);
    const nonce = encrypted.nonce.slice(0, nacl.box.nonceLength / 2);

    const asyncQuery = new AsyncQuery(nonce, encrypted.sharedKey, callback);
    this.session.queue.push(asyncQuery);

    this.write(encrypted.message, error => {
      if (error) {
        process.nextTick(() => this.session.emit('error', error));
      }
    });

    debug('start looking up %s with type %s', hostname, rrtype);
  }

  /**
   * Handler for DNS response.
   * @param {Buffer} message
   * @returns {void}
   */
  onresponse(message) {
    if (message.length < minResponseLength) {
      return;
    }

    const response = dnssec.parse(message);

    if (response.magic.high !== SERV_MAGIC_HIGH && response.magic.low !== SERV_MAGIC_LOW) {
      return;
    }

    debug('got response, size = %s', message.length);

    const clientNonce = response.nonce.slice(0, nacl.box.nonceLength / 2);

    /** @type {AsyncQuery} */
    const querybox = this.session.queue.drop(
      query => Buffer.compare(clientNonce, query.nonce) === 0
    );

    if (querybox === undefined) {
      return;
    }

    let decrypted = null;

    try {
      decrypted = dnssec.decrypt(response.message, response.nonce, querybox.sharedKey);
    } catch (error) {
      process.nextTick(() => querybox.callback(error));
      return;
    }

    debug('decrypt, size = %s', decrypted.length);

    const query = packet.decode(decrypted);
    querybox.callback(null, query);
  }

  /**
   * Send the message through the socket.
   * @param {Buffer} message Message to send.
   * @param {Function} callback
   */
  write(message, callback) {
    if (this.session.connected) {
      this.socket.send(message, 0, message.length, callback);
    } else {
      this.socket.send(
        message,
        0,
        message.length,
        this.session.serverPort,
        this.session.serverAddress,
        callback
      );
    }
  }
};

/**
 * Check sender on non-connected UDP socket.
 * @param {RemoteInfo} rinfo UDP remote info.
 * @param {Session} session DNSCrypt session.
 * @returns {boolean}
 */
function isValidSender(rinfo, session) {
  if (rinfo.address === session.serverAddress && rinfo.port === session.serverPort) {
    return true;
  }

  return false;
}

/**
 * Handle remote certificate.
 * @param {StateMachine} machine
 * @param {Session} session
 * @returns {void}
 */
function onCertificate(machine, session) {
  const response = session.certificatePacket;

  if (response.type !== 'response') {
    throw new Error('Invalid DNS response');
  }

  if (response.rcode !== 'NOERROR') {
    throw new Error('Invalid DNS response');
  }

  if (response.answers.length !== response.questions.length) {
    throw new Error('Invalid DNS response');
  }

  const record = response.answers.find(
    answer => answer.type === 'TXT' && answer.name === session.resolver.providerName
  );

  if (!record) {
    throw new Error('Invalid DNS response');
  }

  /** @type {Buffer[]} */
  const encodedCertificates = Array.isArray(record.data) ? record.data : [record.data];

  if (encodedCertificates.length === 0) {
    throw new Error('Invalid DNS response');
  }

  // Resolver public key.
  const publicKey = Buffer.from(session.resolver.pk, 'hex');

  const reducer = (previous, { certificate }) => {
    if (!previous) {
      return certificate;
    }

    return certificate.serial > previous.serial ? certificate : previous;
  };

  const mapper = bytes => {
    const certificate = cert.parse(bytes);

    if (certificate === null) {
      return null;
    }

    const signed = bytes.slice(4 + 2 + 2 + 64);

    return {
      certificate,
      signed,
    };
  };

  const remoteCertificate = encodedCertificates
    .map(bytes => mapper(bytes))
    .filter(Boolean)
    .filter(({ certificate, signed }) => cert.validate(certificate, signed, publicKey))
    .reduce(reducer, null);

  debug('got certificate', remoteCertificate);

  session.certificate = remoteCertificate;
  machine.next(DNSC_READY);
}
