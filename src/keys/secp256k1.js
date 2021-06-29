'use strict'

const secp256k1 = require('secp256k1')
// @ts-ignore
const sha = require('multihashing-async/src/sha')
const HASH_ALGORITHM = 'sha2-256'

/**
 * @param {import('../random-bytes')} randomBytes
 */
module.exports = (randomBytes) => {
  const privateKeyLength = 32

  /**
   * @returns {Uint8Array}
   */
  function generateKey () {
    let privateKey
    do {
      privateKey = randomBytes(32)
    } while (!secp256k1.privateKeyVerify(privateKey))
    return privateKey
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} msg
   */

  async function hashAndSign (key, msg) {
    const digest = await sha.digest(msg, HASH_ALGORITHM)
    const sig = secp256k1.ecdsaSign(digest, key)
    return secp256k1.signatureExport(sig.signature)
  }

  /**
   * @param {Uint8Array} key
   * @param {Uint8Array} sig
   * @param {Uint8Array} msg
   */
  async function hashAndVerify (key, sig, msg) {
    const digest = await sha.digest(msg, HASH_ALGORITHM)
    sig = secp256k1.signatureImport(sig)
    return secp256k1.ecdsaVerify(sig, digest, key)
  }

  /**
   * @param {Uint8Array} key
   * @returns {Uint8Array}
   */
  function compressPublicKey (key) {
    if (!secp256k1.publicKeyVerify(key)) {
      throw new Error('Invalid public key')
    }
    return secp256k1.publicKeyConvert(key, true)
  }

  /**
   * @param {Uint8Array} key
   * @returns {Uint8Array}
   */
  function decompressPublicKey (key) {
    return secp256k1.publicKeyConvert(key, false)
  }

  /**
   * @param {Uint8Array} key
   */
  function validatePrivateKey (key) {
    if (!secp256k1.privateKeyVerify(key)) {
      throw new Error('Invalid private key')
    }
  }

  /**
   * @param {Uint8Array} key
   */
  function validatePublicKey (key) {
    if (!secp256k1.publicKeyVerify(key)) {
      throw new Error('Invalid public key')
    }
  }

  /**
   * @param {Uint8Array} privateKey
   * @returns {Uint8Array}
   */
  function computePublicKey (privateKey) {
    validatePrivateKey(privateKey)
    return secp256k1.publicKeyCreate(privateKey)
  }

  return {
    generateKey,
    privateKeyLength,
    hashAndSign,
    hashAndVerify,
    compressPublicKey,
    decompressPublicKey,
    validatePrivateKey,
    validatePublicKey,
    computePublicKey
  }
}
