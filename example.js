'use strict';

const DNSCrypt = require('./src/dnscrypt');

const dns = new DNSCrypt().ref();

// PTR -> IP(google.com).in-addr.arpa
// NAPTR -> digitoffice.ru
// CAA -> google.com
// SRV -> _sip._udp.sip.voice.google.com

dns.resolveGeneric('yandex.ru', 'ABC', (error, answer) => {
  if (error) {
    console.error(error);
  } else {
    console.log(answer);
  }

  dns.close();
});

dns.on('error', error => console.error(error));
