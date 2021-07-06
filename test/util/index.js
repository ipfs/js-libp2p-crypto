/* eslint-disable valid-jsdoc */
'use strict'

const { expect } = require('aegir/utils/chai')

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

module.exports = { expectErrCode }
