'use strict';

// const dnscrypt = require('.');
const UDPClient = require('./src/transport/udp-client');
const { Session } = require('./src/session');

// PTR -> IP(google.com).in-addr.arpa
// NAPTR -> digitoffice.ru
// CAA -> google.com
// SRV -> _sip._udp.sip.voice.google.com

const session = new Session();
const dnscrypt = new UDPClient({ session });

dnscrypt.lookup('example.com', 'A', (error, answer) => {
  if (error) {
    console.error(error);
  } else {
    console.log(answer);
  }

  dnscrypt.close();
});
