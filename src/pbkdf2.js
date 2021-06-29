'use strict'

// @ts-ignore
const forgePbkdf2 = require('node-forge/lib/pbkdf2')
// @ts-ignore
const forgeUtil = require('node-forge/lib/util')
const errcode = require('err-code')

/**
 * Maps an IPFS hash name to its node-forge equivalent.
 *
 * See https://github.com/multiformats/multihash/blob/master/hashtable.csv
 *
 * @private
 */
const hashName = {
  sha1: 'sha1',
  'sha2-256': 'sha256',
  'sha2-512': 'sha512'
}

/**
 * Computes the Password-Based Key Derivation Function 2.
 *
 * @param {string} password - The password.
 * @param {string} salt - The salt.
 * @param {number} iterations - Number of iterations to use.
 * @param {number} keySize - The size of the output key in bytes.
 * @param {keyof hashName} hash - The hash name ('sha1', 'sha2-512, ...)
 * @returns {string} - A new password
 */
function pbkdf2 (password, salt, iterations, keySize, hash) {
  const hasher = hashName[hash]
  if (!hasher) {
    const types = Object.keys(hashName).join(' / ')
    throw errcode(new Error(`Hash '${hash}' is unknown or not supported. Must be ${types}`), 'ERR_UNSUPPORTED_HASH_TYPE')
  }
  const dek = forgePbkdf2(
    password,
    salt,
    iterations,
    keySize,
    hasher)
  return forgeUtil.encode64(dek)
}

module.exports = pbkdf2
