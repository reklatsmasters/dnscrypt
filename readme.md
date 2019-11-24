# dnscrypt
[![stability-unstable](https://img.shields.io/badge/stability-unstable-yellow.svg)](https://github.com/emersion/stability-badges#unstable)
[![Build Status](https://travis-ci.com/reklatsmasters/dnscrypt.svg?token=u7sXsR3bTvzyLs6vq3CD&branch=master)](https://travis-ci.com/reklatsmasters/dnscrypt)
[![npm](https://img.shields.io/npm/v/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![node](https://img.shields.io/node/v/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![license](https://img.shields.io/npm/l/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![downloads](https://img.shields.io/npm/dm/dnscrypt.svg)](https://npmjs.org/package/dnscrypt)
[![Coverage Status](https://coveralls.io/repos/github/reklatsmasters/dnscrypt/badge.svg?branch=master)](https://coveralls.io/github/reklatsmasters/dnscrypt?branch=master)

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

## How to

* Use global api `dnscrypt.resolve` for single looking up.
* Use resolver api `dnscrypt.createResolver()` for multiple lookups (_to avoid repeated certificate requests_).

## API

* *`dnscrypt.resolve(hostname[, rrtype], callback): void`*
* *`dnscrypt.resolve(hostname[, rrtype]): Promise`*

See [dns.resolve](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolve_hostname_rrtype_callback).

* *`dnscrypt.resolve4(hostname[, options], callback): void`*
* *`dnscrypt.resolve4(hostname[, options]): Promise`*

See [dns.resolve4](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolve4_hostname_options_callback).

* *`dnscrypt.resolve6(hostname[, options], callback): void`*
* *`dnscrypt.resolve6(hostname[, options]): Promise`*

See [dns.resolve6](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolve6_hostname_options_callback).

* *`dnscrypt.resolveCname(hostname, callback): void`*
* *`dnscrypt.resolveCname(hostname): Promise`*

See [dns.resolveCname](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolvecname_hostname_callback).

* *`dnscrypt.resolveMx(hostname, callback): void`*
* *`dnscrypt.resolveMx(hostname): Promise`*

See [dns.resolveMx](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolvemx_hostname_callback).

* *`dnscrypt.resolveNs(hostname, callback): void`*
* *`dnscrypt.resolveNs(hostname): Promise`*

See [dns.resolveNs](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolvens_hostname_callback).

* *`dnscrypt.resolvePtr(hostname, callback): void`*
* *`dnscrypt.resolvePtr(hostname): Promise`*

See [dns.resolvePtr](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolveptr_hostname_callback).

* *`dnscrypt.resolveSoa(hostname, callback): void`*
* *`dnscrypt.resolveSoa(hostname): Promise`*

See [dns.resolveSoa](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolvesoa_hostname_callback).

* *`dnscrypt.resolveSrv(hostname, callback): void`*
* *`dnscrypt.resolveSrv(hostname): Promise`*

See [dns.resolveSrv](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolvesrv_hostname_callback).

* *`dnscrypt.resolveTxt(hostname, callback): void`*
* *`dnscrypt.resolveTxt(hostname): Promise`*

See [dns.resolveTxt](https://nodejs.org/dist/latest-v12.x/docs/api/dns.html#dns_dns_resolvetxt_hostname_callback).

* *`dnscrypt.getServers(): DNSStamp[]`*

Returns an array of active DNS servers.

* *`dnscrypt.createResolver([options]): Resolver`*

Create a new independent resolver for DNS requests.

  - `options.timeout: number` - The number of milliseconds before a request times out, 2s default.
  - `options.unref: bool` - Call `.unref()` on internal dgram socket.
  - `options.sdns: string` - Use secure DNS resolver instead of default one.

The following methods from the `dnscrypt` module are available:

* *`resolver.resolve(hostname[, rrtype], callback): void`*
* *`resolver.resolve(hostname[, rrtype]): Promise`*
* *`resolver.resolve4(hostname[, options], callback): void`*
* *`resolver.resolve4(hostname[, options]): Promise`*
* *`resolver.resolve6(hostname[, options], callback): void`*
* *`resolver.resolve6(hostname[, options]): Promise`*
* *`resolver.resolveCname(hostname, callback): void`*
* *`resolver.resolveCname(hostname): Promise`*
* *`resolver.resolveMx(hostname, callback): void`*
* *`resolver.resolveMx(hostname): Promise`*
* *`resolver.resolveNs(hostname, callback): void`*
* *`resolver.resolveNs(hostname): Promise`*
* *`resolver.resolvePtr(hostname, callback): void`*
* *`resolver.resolvePtr(hostname): Promise`*
* *`resolver.resolveSoa(hostname, callback): void`*
* *`resolver.resolveSoa(hostname): Promise`*
* *`resolver.resolveSrv(hostname, callback): void`*
* *`resolver.resolveSrv(hostname): Promise`*
* *`resolver.resolveTxt(hostname, callback): void`*
* *`resolver.resolveTxt(hostname): Promise`*
* *`resolver.getServers(): DNSStamp[]`*

* *`resolver.setServers(sdns): void`*

Change the address of internal secure DNS server.

* *`resolver.close(): void`*

Close encrypted DNS session.

## License

MIT, 2019 (c) Dmitriy Tsvettsikh
