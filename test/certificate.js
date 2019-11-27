'use strict';

const packet = require('dns-packet');
const dgram = require('dgram');
const { parse } = require('../src/certificate');

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
