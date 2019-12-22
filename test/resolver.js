'use strict';

jest.mock('../src/dnscrypt');
jest.mock('dnsstamp', () => ({
  DNSStamp: {
    parse: x => x,
  },
}));

const DNSCrypt = require('../src/dnscrypt');
const { createResolver } = require('..');

describe('test custom resolver', () => {
  let resolver;

  const resolve4 = jest.fn().mockImplementation((host, opts, cb) => cb(null, '1.2.3.4'));
  const resolve6 = jest.fn().mockImplementation((host, opts, cb) => cb(null, '2002::1'));
  const resolveCname = jest.fn().mockImplementation((host, cb) => cb(null, 'cname.example.com'));
  const resolveNs = jest.fn().mockImplementation((host, cb) => cb(null, 'ns.example.com'));
  const resolvePtr = jest.fn().mockImplementation((host, cb) => cb(null, 'ptr.example.com'));
  const resolveMx = jest.fn().mockImplementation((host, cb) => cb(null, 'mx.example.com'));
  const resolveSoa = jest.fn().mockImplementation((host, cb) => cb(null, 'soa.example.com'));
  const resolveSrv = jest.fn().mockImplementation((host, cb) => cb(null, 'srv.example.com'));
  const resolveTxt = jest.fn().mockImplementation((host, cb) => cb(null, 'txt.example.com'));
  const resolve = jest.fn().mockImplementation((host, rrtype, cb) => cb(null, '1.example.com'));

  const unref = jest.fn();
  const close = jest.fn();
  const setResolver = jest.fn();
  const ownSdns = 'sdns://1a2b3c4d5e6f';

  beforeAll(() => {
    DNSCrypt.mockImplementation(() => ({
      session: {
        sdns: ownSdns,
      },
      close,
      once: jest.fn(),
      unref,
      setResolver,
      resolve4,
      resolve6,
      resolveCname,
      resolveNs,
      resolvePtr,
      resolveMx,
      resolveSoa,
      resolveSrv,
      resolveTxt,
      resolve,
    }));

    resolver = createResolver();
  });

  beforeEach(() => jest.clearAllMocks());

  test('resolve4', async () => {
    const response = await resolver.resolve4('example.com');
    expect(response).toBe('1.2.3.4');
  });

  test('resolve6', async () => {
    const response = await resolver.resolve6('example.com');
    expect(response).toBe('2002::1');
  });

  test('resolveCname', async () => {
    const response = await resolver.resolveCname('example.com');
    expect(response).toBe('cname.example.com');
  });

  test('resolveNs', async () => {
    const response = await resolver.resolveNs('example.com');
    expect(response).toBe('ns.example.com');
  });

  test('resolvePtr', async () => {
    const response = await resolver.resolvePtr('example.com');
    expect(response).toBe('ptr.example.com');
  });

  test('resolveMx', async () => {
    const response = await resolver.resolveMx('example.com');
    expect(response).toBe('mx.example.com');
  });

  test('resolveSoa', async () => {
    const response = await resolver.resolveSoa('example.com');
    expect(response).toBe('soa.example.com');
  });

  test('resolveSrv', async () => {
    const response = await resolver.resolveSrv('example.com');
    expect(response).toBe('srv.example.com');
  });

  test('resolveTxt', async () => {
    const response = await resolver.resolveTxt('example.com');
    expect(response).toBe('txt.example.com');
  });

  test('resolve', async () => {
    const response = await resolver.resolve('example.com');
    expect(response).toBe('1.example.com');
  });

  test('unref', () => {
    createResolver({ unref: true });

    expect(unref).toBeCalled();
  });

  test('close', () => {
    const rslv = createResolver();
    rslv.close();

    expect(close).toBeCalled();
  });

  test('setResolver', () => {
    const sdns = 'sdns://123456';

    const rslv = createResolver();
    rslv.setServers(sdns);

    expect(setResolver).toBeCalledWith(sdns);
  });

  test('getServers', () => {
    const sdns = resolver.getServers();
    expect(sdns).toStrictEqual([ownSdns]);
  });
});
