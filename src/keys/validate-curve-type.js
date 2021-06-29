'use strict'

const errcode = require('err-code')

/**
 *
 * @param {string[]} curveTypes
 * @param {string} type
 */
module.exports = function (curveTypes, type) {
  if (!curveTypes.includes(type)) {
    const names = curveTypes.join(' / ')
    throw errcode(new Error(`Unknown curve: ${type}. Must be ${names}`), 'ERR_INVALID_CURVE')
  }
}
