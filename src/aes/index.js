'use strict'

const ciphers = require('./ciphers')
const cipherMode = require('./cipher-mode')

/**
 * Create a new AES Cipher.
 *
 * @param {Uint8Array} key - The key, if length 16 then AES 128 is used. For length 32, AES 256 is used.
 * @param {Uint8Array} iv - Must have length 16.
 * @returns {Promise<import('libp2p-interfaces/src/crypto/types').Cipher>}
 */
exports.create = async function (key, iv) { // eslint-disable-line require-await
  const mode = cipherMode(key)
  const cipher = ciphers.createCipheriv(mode, key, iv)
  const decipher = ciphers.createDecipheriv(mode, key, iv)

  const res = {
    /**
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async encrypt (data) { // eslint-disable-line require-await
      return cipher.update(data)
    },

    /**
     * @param {Uint8Array} data
     * @returns {Promise<Uint8Array>}
     */
    async decrypt (data) { // eslint-disable-line require-await
      return decipher.update(data)
    }
  }

  return res
}
