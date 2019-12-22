'use strict';

jest.mock('../src/dnscrypt');
jest.mock('dnsstamp', () => ({
  DNSStamp: {
    parse: x => x,
  },
}));

const DNSCrypt = require('../src/dnscrypt');
const dnscrypt = require('..');
const { DEFAULT_RESOLVER } = require('../src/session');

describe('should resolve', () => {
  beforeEach(() => jest.clearAllMocks());

  describe('resolve4', () => {
    const error = null;
    const response = '1.2.3.4';

    const resolve4 = jest.fn().mockImplementation((host, opts, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolve4,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolve4('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolve6', () => {
    const error = null;
    const response = '2002::1';

    const resolve6 = jest.fn().mockImplementation((host, opts, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolve6,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolve6('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolveCname', () => {
    const error = null;
    const response = 'myhost.name';

    const resolveCname = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolveCname,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolveCname('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolveNs', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolveNs = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolveNs,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolveNs('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolvePtr', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolvePtr = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolvePtr,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolvePtr('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolveMx', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolveMx = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolveMx,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolveMx('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolveSoa', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolveSoa = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolveSoa,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolveSoa('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolveSrv', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolveSrv = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolveSrv,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolveSrv('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolveTxt', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolveTxt = jest.fn().mockImplementation((host, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolveTxt,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolveTxt('example.com');
      expect(addr).toBe(response);
    });
  });

  describe('resolve', () => {
    const error = null;
    const response = 'mynshost.name';

    const resolve = jest.fn().mockImplementation((host, rrtype, cb) => cb(error, response));

    beforeAll(() => {
      DNSCrypt.mockImplementation(() => ({
        close: jest.fn(),
        once: jest.fn(),
        resolve,
      }));
    });

    test('should work', async () => {
      const addr = await dnscrypt.resolve('example.com');
      expect(addr).toBe(response);
    });

    test('should work with rrtype', async () => {
      const addr = await dnscrypt.resolve('example.com', 'A');
      expect(addr).toBe(response);
    });
  });
});

test('getServers', () => {
  const response = dnscrypt.getServers();
  expect(response).toStrictEqual([DEFAULT_RESOLVER]);
});
