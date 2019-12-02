'use strict';

const packet = require('dns-packet');
const dgram = require('dgram');
const nacl = require('tweetnacl');
const { BinaryStream } = require('binary-data');
const { parse, validate } = require('../src/certificate');

/**
 * Get certificate.
 * @param {string} host
 * @param {number} port
 * @param {string} provider
 * @returns {Promise<Buffer[]>}
 */
function requestCertificate(host, port, provider) {
  const query = packet.encode({
    id: 1,
    type: 'query',
    questions: [
      {
        type: 'TXT',
        name: provider,
      },
    ],
  });

  const socket = dgram.createSocket('udp4').unref();

  return new Promise((resolve, reject) => {
    socket.send(query, port, host, err => {
      if (err) {
        reject(err);
      }
    });

    socket.once('message', message => {
      socket.close();

      const response = packet.decode(message);

      const record = response.answers.find(
        answer => answer.type === 'TXT' && answer.name === provider
      );

      const certificates = Array.isArray(record.data) ? record.data : [record.data];
      resolve(certificates);
    });
  });
}

// docker run --name=dnscrypt-server -p 443:443/udp -p 443:443/tcp --ulimit nofile=90000:90000 --restart=unless-stopped -v ${PWD}/keys:/opt/encrypted-dns/etc/keys jedisct1/dnscrypt-server init -N example.com -E 192.168.1.1:443

test('should parse', async () => {
  const certificates = await requestCertificate('9.9.9.10', 8443, '2.dnscrypt-cert.quad9.net');

  const encodedCertificate = parse(certificates[0]);
  expect(encodedCertificate).not.toBeNull();

  expect(encodedCertificate.certMagic).toBeGreaterThan(0);
  expect(encodedCertificate.esVersion).toBeGreaterThan(0);
  expect(encodedCertificate.minProtocol).toBe(0);
  expect(encodedCertificate.signature).toBeInstanceOf(Buffer);
  expect(encodedCertificate.resolverPk).toBeInstanceOf(Buffer);
  expect(encodedCertificate.clientMagic).toBeInstanceOf(Buffer);
  expect(encodedCertificate.serial).toBeGreaterThan(0);
  expect(encodedCertificate.ts.start).toBeLessThan(~~(Date.now() / 1e3));
  expect(encodedCertificate.ts.end).toBeGreaterThan(~~(Date.now() / 1e3));
});

test('should not parse', () => {
  const cert = Buffer.allocUnsafe(10);

  expect(parse(cert)).toBeNull();
  expect(parse([cert])).toBeNull();
});

describe('validate certificate', () => {
  test('check magic', () => {
    const certificate = {
      certMagic: Buffer.from('DNSC').readUInt32BE() + 1,
    };

    expect(validate(certificate)).toBe(false);
  });

  test('check protocol', () => {
    const certificate = {
      certMagic: Buffer.from('DNSC').readUInt32BE(),
      minProtocol: 1,
    };

    expect(validate(certificate)).toBe(false);
  });

  test('check es version', () => {
    const certificate = {
      certMagic: Buffer.from('DNSC').readUInt32BE(),
      minProtocol: 0,
      esVersion: 0,
    };

    expect(validate(certificate)).toBe(false);
  });

  test('check pk', () => {
    const { publicKey } = nacl.sign.keyPair();
    const pubkey = Buffer.from(publicKey.buffer, publicKey.byteOffset, publicKey.byteLength);

    const certificate = {
      certMagic: Buffer.from('DNSC').readUInt32BE(),
      minProtocol: 0,
      esVersion: 1,
      signature: null,
      resolverPk: pubkey,
      clientMagic: Buffer.allocUnsafe(8),
      serial: Math.trunc(Math.random() * 1e3),
      ts: {
        start: Math.trunc((Date.now() - 60e3) / 1e3),
        end: Math.trunc((Date.now() + 60e3) / 1e3),
      },
    };

    expect(validate(certificate)).toBe(false);
  });

  test('check ts', () => {
    const { publicKey } = nacl.sign.keyPair();
    const pubkey = Buffer.from(publicKey.buffer, publicKey.byteOffset, publicKey.byteLength);

    const certificate = {
      certMagic: Buffer.from('DNSC').readUInt32BE(),
      minProtocol: 0,
      esVersion: 1,
      signature: null,
      resolverPk: pubkey,
      clientMagic: pubkey.slice(0, 8),
      serial: Math.trunc(Math.random() * 1e3),
      ts: {
        start: Math.trunc((Date.now() + 60e3) / 1e3),
        end: Math.trunc((Date.now() - 60e3) / 1e3),
      },
    };

    expect(validate(certificate)).toBe(false);
  });

  test('should be valid', () => {
    const { publicKey, secretKey } = nacl.sign.keyPair();
    const pubkey = Buffer.from(publicKey.buffer, publicKey.byteOffset, publicKey.byteLength);
    const signature = new BinaryStream();

    const certificate = {
      certMagic: Buffer.from('DNSC').readUInt32BE(),
      minProtocol: 0,
      esVersion: 1,
      signature: null,
      resolverPk: pubkey,
      clientMagic: pubkey.slice(0, 8),
      serial: Math.trunc(Math.random() * 1e3),
      ts: {
        start: Math.trunc((Date.now() - 60e3) / 1e3),
        end: Math.trunc((Date.now() + 60e3) / 1e3),
      },
    };

    signature.append(certificate.resolverPk);
    signature.append(certificate.clientMagic);
    signature.writeUInt32BE(certificate.serial);
    signature.writeUInt32BE(certificate.ts.start);
    signature.writeUInt32BE(certificate.ts.end);

    certificate.signature = nacl.sign.detached(signature.slice(), secretKey);

    expect(publicKey.byteLength).toBe(32);
    expect(certificate.signature.byteLength).toBe(64);

    expect(validate(certificate, signature.slice(), pubkey)).toBe(true);
  });
});
