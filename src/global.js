'use strict';

const dnsstamp = require('dnsstamp').DNSStamp;
const { fromCallback } = require('universalify');
const { DEFAULT_RESOLVER } = require('./session');
const { Resolver } = require('./resolver');

const resolve = fromCallback((hostname, rrtype, callback) => {
  const resolver = new Resolver();
  resolver.resolve(hostname, rrtype, createCallback(resolver, callback));
});

const resolve4 = fromCallback((hostname, options, callback) => {
  const resolver = new Resolver();
  resolver.resolve4(hostname, options, createCallback(resolver, callback));
});

const resolve6 = fromCallback((hostname, options, callback) => {
  const resolver = new Resolver();
  resolver.resolve6(hostname, options, createCallback(resolver, callback));
});

const resolveCname = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolveCname(hostname, createCallback(resolver, callback));
});

const resolveNs = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolveNs(hostname, createCallback(resolver, callback));
});

const resolvePtr = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolvePtr(hostname, createCallback(resolver, callback));
});

const resolveMx = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolveMx(hostname, createCallback(resolver, callback));
});

const resolveSoa = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolveSoa(hostname, createCallback(resolver, callback));
});

const resolveSrv = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolveSrv(hostname, createCallback(resolver, callback));
});

const resolveTxt = fromCallback((hostname, callback) => {
  const resolver = new Resolver();
  resolver.resolveTxt(hostname, createCallback(resolver, callback));
});

module.exports = {
  resolve,
  resolve4,
  resolve6,
  resolveCname,
  resolveNs,
  resolvePtr,
  resolveMx,
  resolveSoa,
  resolveSrv,
  resolveTxt,
  getServers,
};

/**
 * Create wrapper for callback.
 * @param {Resolver} resolver
 * @param {Function} callback
 * @returns {Function}
 */
function createCallback(resolver, callback) {
  return function _callback(error, data) {
    resolver.close();

    if (error) {
      callback(error);
    } else {
      callback(null, data);
    }
  };
}

/**
 * Returns an array of active DNS servers.
 * @returns {DNSStamp[]}
 */
function getServers() {
  return [dnsstamp.parse(DEFAULT_RESOLVER)];
}
