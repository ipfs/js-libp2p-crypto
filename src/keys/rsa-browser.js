'use strict'

const webcrypto = require('../webcrypto')
const randomBytes = require('../random-bytes')
const uint8ArrayToString = require('uint8arrays/to-string')
const uint8ArrayFromString = require('uint8arrays/from-string')

exports.utils = require('./rsa-utils')

/**
 * @param {number} bits
 */
exports.generateKey = async function (bits) {
  const pair = await webcrypto.get().subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: 'SHA-256' }
    },
    true,
    ['sign', 'verify']
  )

  const keys = await exportKey(pair)

  return {
    privateKey: keys[0],
    publicKey: keys[1]
  }
}

/**
 * @param {JsonWebKey} key
 */
exports.unmarshalPrivateKey = async function (key) {
  const privateKey = await webcrypto.get().subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    true,
    ['sign']
  )

  const pair = [
    privateKey,
    await derivePublicFromPrivate(key)
  ]

  const keys = await exportKey({
    privateKey: pair[0],
    publicKey: pair[1]
  })

  return {
    privateKey: keys[0],
    publicKey: keys[1]
  }
}

exports.getRandomValues = randomBytes

/**
 * @param {JsonWebKey} key
 * @param {Uint8Array} msg
 */
exports.hashAndSign = async function (key, msg) {
  const privateKey = await webcrypto.get().subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    false,
    ['sign']
  )

  const sig = await webcrypto.get().subtle.sign(
    { name: 'RSASSA-PKCS1-v1_5' },
    privateKey,
    Uint8Array.from(msg)
  )

  return new Uint8Array(sig)
}

/**
 *
 * @param {JsonWebKey} key
 * @param {Uint8Array} sig
 * @param {Uint8Array} msg
 * @returns
 */
exports.hashAndVerify = async function (key, sig, msg) {
  const publicKey = await webcrypto.get().subtle.importKey(
    'jwk',
    key,
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    false,
    ['verify']
  )

  return webcrypto.get().subtle.verify(
    { name: 'RSASSA-PKCS1-v1_5' },
    publicKey,
    sig,
    msg
  )
}

/**
 *
 * @param {{privateKey: CryptoKey, publicKey: CryptoKey}} pair
 */
function exportKey (pair) {
  return Promise.all([
    webcrypto.get().subtle.exportKey('jwk', pair.privateKey),
    webcrypto.get().subtle.exportKey('jwk', pair.publicKey)
  ])
}

/**
 * @param {JsonWebKey} jwKey
 */
function derivePublicFromPrivate (jwKey) {
  return webcrypto.get().subtle.importKey(
    'jwk',
    {
      kty: jwKey.kty,
      n: jwKey.n,
      e: jwKey.e
    },
    {
      name: 'RSASSA-PKCS1-v1_5',
      hash: { name: 'SHA-256' }
    },
    true,
    ['verify']
  )
}

/*

RSA encryption/decryption for the browser with webcrypto workarround
"bloody dark magic. webcrypto's why."

Explanation:
  - Convert JWK to nodeForge
  - Convert msg Uint8Array to nodeForge buffer: ByteBuffer is a "binary-string backed buffer", so let's make our Uint8Array a binary string
  - Convert resulting nodeForge buffer to Uint8Array: it returns a binary string, turn that into a Uint8Array

*/

const { jwk2pub, jwk2priv } = require('./jwk2pem')

/**
 * @param {Uint8Array} bytes
 */
const encodeAscii = bytes => uint8ArrayToString(Uint8Array.from(bytes), 'ascii')

/**
 * @param {string} text
 */
const decodeAscii = text => uint8ArrayFromString(text, 'ascii')

/**
 * @param {import('pem-jwk').RSA_JWK} key
 * @param {Uint8Array} msg
 */
exports.encrypt = (key, msg) =>
  decodeAscii(jwk2pub(key).encrypt(encodeAscii(msg)))

/**
 * @param {import('pem-jwk').RSA_JWK} key
 * @param {Uint8Array} msg
 */
exports.decrypt = (key, msg) =>
  decodeAscii(jwk2priv(key).decrypt(encodeAscii(msg)))
