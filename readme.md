# dnscrypt
[![Build Status](https://travis-ci.com/reklatsmasters/dnscrypt.svg?branch=master)](https://travis-ci.com/reklatsmasters/dnscrypt)
[![npm](https://img.shields.io/npm/v/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![node](https://img.shields.io/node/v/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![license](https://img.shields.io/npm/l/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![downloads](https://img.shields.io/npm/dm/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)

<p align='center'>
  <img src='dnscrypt.png' width='350' alt='dnscrypt logo' />
  <p align='center'>DNSCrypt - authenticated and encrypted DNS client for nodejs</p>
</p>

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

// Supports both callback and promise-based styles.
await dnscrypt.resolve4('example.com');

const resolver = dnscrypt.createResolver({ timeout: 1e3 });
```

## License

MIT, 2019 (c) Dmitriy Tsvettsikh
