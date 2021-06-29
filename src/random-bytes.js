'use strict'

// @ts-ignore - not typed
const randomBytes = require('iso-random-stream/src/random')
const errcode = require('err-code')

/**
 *
 * Generates a Uint8Array populated by random bytes.
 *
 * @param {number} length - The size of the random bytes Uint8Array.
 * @returns {Uint8Array}
 */
module.exports = function (length) {
  if (isNaN(length) || length <= 0) {
    throw errcode(new Error('random bytes length must be a Number bigger than 0'), 'ERR_INVALID_LENGTH')
  }
  return randomBytes(length)
}
