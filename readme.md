# dnscrypt
[![Build Status](https://travis-ci.com/reklatsmasters/dnscrypt.svg?branch=master)](https://travis-ci.com/reklatsmasters/dnscrypt)
[![npm](https://img.shields.io/npm/v/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![node](https://img.shields.io/node/v/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![license](https://img.shields.io/npm/l/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![downloads](https://img.shields.io/npm/dm/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)

DNSCrypt - authenticated and encrypted DNS client in nodejs.

## Usage

```js
const dnscrypt = require('dnscrypt');

dnscrypt.resolve('example.com', (err, addresses) => {
  if (err) {
    console.error(err);
  } else {
    console.log(addresses);
  }
});

const resolver = dnscrypt.createResolver({ timeout: 1e3 });
```

## License

MIT, 2019 (c) Dmitriy Tsvettsikh
