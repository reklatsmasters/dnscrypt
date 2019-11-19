'use strict';

const dnscrypt = require('.');

// PTR -> IP(google.com).in-addr.arpa
// NAPTR -> digitoffice.ru
// CAA -> google.com
// SRV -> _sip._udp.sip.voice.google.com

dnscrypt.resolve('google.com', 'CAA', (error, answer) => {
  if (error) {
    console.error(error);
  } else {
    console.log(answer);
  }
});
