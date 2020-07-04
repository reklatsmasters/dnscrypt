'use strict';

const { createResolver, Resolver } = require('./resolver');
const globalDns = require('./global');

module.exports = {
  createResolver,
  Resolver,
  ...globalDns,
};
