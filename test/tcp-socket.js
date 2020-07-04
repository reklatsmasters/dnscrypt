'use strict';

const net = require('net');
const TCPSocket = require('../src/transport/tcp-socket');

describe('tcp socket', () => {
  const target = net.createServer();

  beforeAll((done) => {
    target.once('error', done);
    target.listen(0, 'localhost', done);
  });

  afterAll((done) => {
    target.close(done);
  });

  it('should work', (done) => {
    expect.assertions(2);

    const socket = new TCPSocket(target.address());
    const data = Buffer.allocUnsafe(10);

    target.once('connection', (connection) => {
      connection.once('data', (message) => {
        expect(message).toEqual(data);
        done();
      });
    });

    socket.write(data, (err) => {
      expect(err).toBeFalsy();

      socket.close();
    });
  });
});
