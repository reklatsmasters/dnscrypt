'use strict';

const { createResolver, Resolver } = require('./resolver');
const dns = require('./dns');

module.exports = {
  createResolver,
  Resolver,
  ...dns,
};
