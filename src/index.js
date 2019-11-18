'use strict';

const { createResolver } = require('./resolver');
const dns = require('./dns');

module.exports = {
  createResolver,
  ...dns,
};
