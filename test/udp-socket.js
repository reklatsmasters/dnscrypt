'use strict';

const dgram = require('dgram');
const UDPSocket = require('../src/transport/udp-socket');

describe('udp socket', () => {
  const target = dgram.createSocket('udp4');

  beforeAll(done => {
    target.once('error', done);
    target.bind(0, 'localhost', done);
  });

  afterAll(done => {
    target.close(done);
  });

  it('should work', done => {
    expect.assertions(3);

    const socket = new UDPSocket(target.address());
    const data = Buffer.allocUnsafe(10);

    socket.write(data, (err, bytes) => {
      expect(err).toBeFalsy();
      expect(bytes).toEqual(data.length);

      socket.close();
    });

    target.once('message', message => {
      expect(message).toEqual(data);
      done();
    });
  });
});
