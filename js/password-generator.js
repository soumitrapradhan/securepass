/*
 * SecurePass - password-generator.js
 * ----------------------------------
 * Generates passwords with the Web Crypto API (crypto.getRandomValues),
 * which is a cryptographically secure random number generator.
 * Math.random() is NEVER used because it is predictable and not safe for passwords.
 */
(function (global) {
  'use strict';

  const SETS = {
    upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lower:   'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    special: '!@#$%^&*()-_=+[]{}<>?'
  };

  function getCrypto() {
    const c = global.crypto || global.msCrypto;
    if (!c || typeof c.getRandomValues !== 'function') {
      throw new Error('Web Crypto API is not available in this browser.');
    }
    return c;
  }

  /**
   * Returns a uniformly distributed random integer in [0, max).
   * Uses rejection sampling to avoid "modulo bias", which would make
   * some characters slightly more likely than others.
   */
  function secureRandomInt(max) {
    if (!Number.isInteger(max) || max <= 0 || max > 0xFFFFFFFF) {
      throw new RangeError('max must be an integer between 1 and 2^32');
    }
    const crypto = getCrypto();
    const buffer = new Uint32Array(1);
    const limit = Math.floor(0x100000000 / max) * max; // largest multiple of max <= 2^32
    do {
      crypto.getRandomValues(buffer);
    } while (buffer[0] >= limit);
    return buffer[0] % max;
  }

  function pickChar(set) {
    return set.charAt(secureRandomInt(set.length));
  }

  /** Fisher-Yates shuffle driven by secure random numbers. */
  function secureShuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      const tmp = array[i];
      array[i] = array[j];
      array[j] = tmp;
    }
    return array;
  }

  /**
   * options: { length, upper, lower, numbers, special }
   * Throws an Error if no character type is selected.
   */
  function generate(options) {
    const opts = options || {};
    const length = Math.max(8, Math.min(32, parseInt(opts.length, 10) || 16));

    const selected = Object.keys(SETS).filter(function (k) { return opts[k]; });
    if (selected.length === 0) {
      throw new Error('Select at least one character type.');
    }

    const pool = selected.map(function (k) { return SETS[k]; }).join('');
    const result = [];

    // 1. Guarantee at least one character from every selected category.
    selected.forEach(function (k) { result.push(pickChar(SETS[k])); });

    // 2. Fill the remaining positions from the combined pool.
    while (result.length < length) result.push(pickChar(pool));

    // 3. Shuffle so the guaranteed characters are not always at the start.
    return secureShuffle(result).join('');
  }

  const api = { generate: generate, secureRandomInt: secureRandomInt, SETS: SETS };
  global.PasswordGenerator = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
