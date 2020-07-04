'use strict';

const Emitter = require('events');
const uset = require('unordered-set');

/**
 * Smart storage for pending queries.
 */
class TimedQueue extends Emitter {
  /**
   * @class {TimedQueue}
   * @param {number} time Time in ms to wait for query.
   */
  constructor(time) {
    super();

    this.ms = time;
    this.timer = null;
    this.queue = [];

    this._timeout = this.timeout.bind(this);
  }

  /**
   * Reset the timer.
   */
  reset() {
    if (this.timer === null) {
      this.timer = setTimeout(this._timeout, this.ms);
    } else {
      this.timer.refresh();
    }
  }

  /**
   * Add the value to the queue.
   * @param {*} data
   */
  push(data) {
    uset.add(this.queue, {
      data,
      timeout: Date.now() + this.ms,
      _index: 0, // required for `unordered-set`
    });

    if (this.timer === null) {
      this.reset();
    }
  }

  /**
   * Find the query and remove it.
   * @param {Function} predicate
   * @returns {*}
   */
  drop(predicate) {
    if (typeof predicate !== 'function') {
      throw new TypeError('Argument "predicate" should be a function');
    }

    const item = this.queue.find((value, i) => predicate(value.data, i));

    if (item === undefined) {
      return;
    }

    uset.remove(this.queue, item);

    if (this.queue.length === 0 && this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    return item.data;
  }

  /**
   * Remove pending queries and timer.
   * @returns {Object[]}
   */
  clear() {
    const queue = this.queue.slice();
    this.queue.length = 0;

    if (this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    return queue.map((value) => value.data);
  }

  /**
   * Remove items by timeout.
   */
  timeout() {
    if (this.queue.length === 0 && this.timer !== null) {
      clearTimeout(this.timer);
      this.timer = null;
      return;
    }

    const removed = [];
    const now = Date.now();

    this.queue.forEach((item) => {
      if (item.timeout <= now) {
        removed.push(item);
        this.emit('timeout', item.data);
      }
    });

    removed.forEach((item) => uset.remove(this.queue, item));

    if (this.queue.length !== 0) {
      this.reset();
    }
  }
}

module.exports = {
  TimedQueue,
};
