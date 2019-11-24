'use strict';

const { TimedQueue } = require('../src/timed-queue');

test('should add data', () => {
  const storage = new TimedQueue(1e3);

  storage.push(5);
  expect(storage.queue.length).toBe(1);
  expect(storage.timer).not.toBe(null);

  clearTimeout(storage.timer);
});

test('should drop data', () => {
  const storage = new TimedQueue(1e3);

  storage.push(4);
  storage.push(8);
  storage.push(15);

  const res = storage.drop(value => value === 15);
  expect(res).toBe(15);
  expect(storage.queue.length).toEqual(2);
  expect(storage.timer).not.toBe(null);

  clearTimeout(storage.timer);
});

test('should drop last data', () => {
  const storage = new TimedQueue(1e3);

  storage.push(15);

  const res = storage.drop(value => value === 15);
  expect(res).toBe(15);
  expect(storage.queue.length).toEqual(0);
  expect(storage.timer).toBe(null);
});

test('should drop unknown data', () => {
  const storage = new TimedQueue(1e3);

  const res = storage.drop(value => value === 15);
  expect(res).toBe(undefined);
  expect(storage.queue.length).toEqual(0);
  expect(storage.timer).toBe(null);
});

test('should clear', () => {
  const storage = new TimedQueue(1e3);

  storage.push(4);
  storage.push(8);

  const res = storage.clear();
  expect(storage.queue.length).toEqual(0);
  expect(storage.timer).toBe(null);
  expect(res).toEqual([4, 8]);
});

test('should handle time outs', done => {
  expect.assertions(4);

  const storage = new TimedQueue(1e3);
  const callback = jest.fn();

  storage.on('timeout', callback);
  storage.push(4);

  setTimeout(() => {
    storage.push(8);
  }, 300);

  setTimeout(() => {
    expect(callback).toBeCalledTimes(1);
    expect(callback).toBeCalledWith(4);
    expect(storage.queue.length).toEqual(1);
    expect(storage.timer).not.toBe(null);

    done();
  }, 1010);
});
