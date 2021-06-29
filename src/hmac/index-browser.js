'use strict'

const webcrypto = require('../webcrypto')
const lengths = require('./lengths')

const hashTypes = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512'
}

/**
 *
 * @param {CryptoKey} key
 * @param {Uint8Array} data
 */
const sign = async (key, data) => {
  const buf = await webcrypto.get().subtle.sign({ name: 'HMAC' }, key, data)
  return new Uint8Array(buf)
}

/**
 * @typedef {import('./index').HashType} HashType
 *
 * @param {HashType} hashType
 * @param {Uint8Array} secret
 * @returns {Promise<import('libp2p-interfaces/src/crypto/types').Hasher>}
 */

exports.create = async function (hashType, secret) {
  const hash = hashTypes[hashType]

  const key = await webcrypto.get().subtle.importKey(
    'raw',
    secret,
    {
      name: 'HMAC',
      hash: { name: hash }
    },
    false,
    ['sign']
  )

  return {
    async digest (data) { // eslint-disable-line require-await
      return sign(key, data)
    },
    length: lengths[hashType]
  }
}
