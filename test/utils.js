'use strict';

const { padLength, padRight, unpadRight } = require('../src/utils');

test('pad length', () => {
  expect(padLength(Buffer.allocUnsafe(5), 5, 5)).toBe(0);
  expect(padLength(Buffer.allocUnsafe(5), 5, 9)).toBe(4);
  expect(padLength(Buffer.allocUnsafe(11), 5, 2)).toBe(4);
});

test('pad right', () => {
  const buf = Buffer.allocUnsafe(5);

  expect(padRight(buf, 5, 5)).toBe(buf);
  expect(padRight(buf, 5, 9).length).toBe(buf.length + 4);
  expect(padRight(buf, 5, 9)).not.toBe(buf);
});

test('unpad right', () => {
  const buf = Buffer.alloc(10, 1);
  buf[8] = 0x80;
  buf[9] = 0;

  expect(unpadRight(buf)).toEqual(buf.slice(0, 8));

  const buf2 = Buffer.alloc(10, 1);
  expect(unpadRight(buf2)).toBe(buf2);
});
