/* eslint-disable valid-jsdoc */
'use strict'

const chai = require('chai')
const expect = chai.expect

// @ts-check
/**
 * @type {function(any, string): Promise<void>}
 */
const expectErrCode = async (p, code) => {
  try {
    await p
  } catch (err) {
    expect(err).to.have.property('code', code)
    return
  }
  expect.fail(`Expected error with code ${code} but no error thrown`)
}

/**
 * @template {string|number|null|boolean} T
 * @param {T} value
 * @returns {T}
 */

const the = value => value

module.exports = { expectErrCode, the }
