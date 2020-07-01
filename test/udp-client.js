'use strict';

const UDPClient = require('../src/transport/udp-client');
const { Session } = require('../src/session');

describe('udp client', () => {
  test('should work', done => {
    const session = new Session(4e3);
    const client = new UDPClient({
      session,
    });

    client.open(err => {
      expect(err).toBeFalsy();
      expect(session.certificate).not.toBeNull();

      client.close(done);
    });
  });
});
