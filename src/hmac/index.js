'use strict'

const crypto = require('crypto')
const lengths = require('./lengths')

/**
 * Maps an IPFS hash name to its node-forge equivalent.
 * See https://github.com/multiformats/multihash/blob/master/hashtable.csv
 *
 * @typedef {"SHA1" | "SHA256" | "SHA512"} HashType
 */

/**
 * Create a new HMAC Digest.
 *
 * @param {HashType} hash
 * @param {Uint8Array} secret
 * @returns {Promise<import('libp2p-interfaces/src/crypto/types').Hasher>}
 */
exports.create = async function (hash, secret) { // eslint-disable-line require-await
  const res = {
    /**
     *
     * @param {Uint8Array} data
     */
    async digest (data) { // eslint-disable-line require-await
      const hmac = crypto.createHmac(hash.toLowerCase(), secret)
      hmac.update(data)
      return hmac.digest()
    },
    length: lengths[hash]
  }

  return res
}
