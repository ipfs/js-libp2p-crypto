'use strict'

const crypto = require('crypto')
const errcode = require('err-code')
const randomBytes = require('../random-bytes')

/**
 * @typedef {import('pem-jwk').RSA_JWK} RSA_JWK
 */

// @ts-check
/**
 * @type {typeof import('keypair').keypair}
 */
let keypair
try {
  if (process.env.LP2P_FORCE_CRYPTO_LIB === 'keypair') {
    throw new Error('Force keypair usage')
  }
  // @ts-ignore

  const ursa = require('ursa-optional') // throws if not compiled
  /**
   * @param {{bits?: number}} options
   */
  keypair = ({ bits } = {}) => {
    const key = ursa.generatePrivateKey(bits)
    return {
      private: key.toPrivatePem(),
      public: key.toPublicPem()
    }
  }
} catch (e) {
  if (process.env.LP2P_FORCE_CRYPTO_LIB === 'ursa') {
    throw e
  }

  // @ts-ignore
  keypair = require('keypair')
}
const pemToJwk = require('pem-jwk').pem2jwk
const jwkToPem = require('pem-jwk').jwk2pem

exports.utils = require('./rsa-utils')

/**
 * @param {number} bits
 */
exports.generateKey = async function (bits) { // eslint-disable-line require-await
  const key = keypair({ bits })
  return {
    privateKey: pemToJwk(key.private),
    publicKey: pemToJwk(key.public)
  }
}

/**
 * @param {RSA_JWK} key
 */
exports.unmarshalPrivateKey = async function (key) { // eslint-disable-line require-await
  if (!key) {
    throw errcode(new Error('Missing key parameter'), 'ERR_MISSING_KEY')
  }
  return {
    privateKey: key,
    publicKey: {
      kty: key.kty,
      n: key.n,
      e: key.e
    }
  }
}

exports.getRandomValues = randomBytes

/**
 *
 * @param {RSA_JWK} key
 * @param {Uint8Array} msg
 * @returns {Promise<Uint8Array>}
 */
exports.hashAndSign = async function (key, msg) { // eslint-disable-line require-await
  const sign = crypto.createSign('RSA-SHA256')
  sign.update(msg)
  const pem = jwkToPem(key)
  return sign.sign(pem)
}

/**
 *
 * @param {RSA_JWK} key
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @returns {Promise<boolean>}
 */
exports.hashAndVerify = async function (key, sig, msg) { // eslint-disable-line require-await
  const verify = crypto.createVerify('RSA-SHA256')
  verify.update(msg)
  const pem = jwkToPem(key)
  return verify.verify(pem, sig)
}

const padding = crypto.constants.RSA_PKCS1_PADDING

/**
 * @param {RSA_JWK} key
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
exports.encrypt = function (key, bytes) {
  return crypto.publicEncrypt({ key: jwkToPem(key), padding }, bytes)
}

/**
 * @param {RSA_JWK} key
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
exports.decrypt = function (key, bytes) {
  return crypto.privateDecrypt({ key: jwkToPem(key), padding }, bytes)
}
