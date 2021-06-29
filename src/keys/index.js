'use strict'

const keysPBM = require('./keys')
// @ts-ignore
require('node-forge/lib/asn1')
// @ts-ignores
require('node-forge/lib/pbe')
/** @type {import('node-forge')} */
// @ts-ignore
const forge = require('node-forge/lib/forge')
const errcode = require('err-code')
const uint8ArrayFromString = require('uint8arrays/from-string')

const importer = require('./importer')

const supportedKeys = {
  rsa: require('./rsa-class'),
  ed25519: require('./ed25519-class'),
  secp256k1: require('./secp256k1-class')(keysPBM, require('../random-bytes'))
}

/**
 * @template {KeyType} Type
 * @typedef {Type extends 'RSA' ? import('./rsa-class').PrivateKey :
 * Type extends 'Ed25519' ? import('./ed25519-class').PrivateKey :
 * Type extends 'secp256k1' ? import('./secp256k1-class').PrivateKey :
 * never} KeyByType
 */

/**
 * @typedef {"Ed25519" | "RSA" | "secp256k1"} KeyType
 */

const ErrMissingSecp256K1 = {
  message: 'secp256k1 support requires libp2p-crypto-secp256k1 package',
  code: 'ERR_MISSING_PACKAGE'
}

/**
 * @template {KeyType} Type
 * @param {Type} type
 * @returns {any}
 */
function typeToKey (type) {
  // @ts-expect-error - No index signature on supportedKeys
  const key = supportedKeys[type.toLowerCase()]
  if (!key) {
    const supported = Object.keys(supportedKeys).join(' / ')
    throw errcode(new Error(`invalid or unsupported key type ${type}. Must be ${supported}`), 'ERR_UNSUPPORTED_KEY_TYPE')
  }
  return key
}

/**
 * Generates a keypair of the given type and bitsize
 *
 * @deprecated - seems to abstract over key type but then bits are ignored by
 * generateKeyPair
 *
 * @template {KeyType} Type
 * @param {Type} type
 * @param {number} [bits]
 * @returns {Promise<KeyByType<Type>>}
 */
const generateKeyPair = async (type, bits) => { // eslint-disable-line require-await
  return typeToKey(type).generateKeyPair(bits)
}

/**
 * Generates a keypair of the given type and bitsize seed is a 32 byte uint8array
 *
 * @deprecated - This is not generic and does not seems be of much use.
 * @template {"Ed25519"} Type
 * @param {Type} type
 * @param {Uint8Array} seed
 * @returns {Promise<KeyByType<Type>>}
 */
const generateKeyPairFromSeed = async (type, seed) => { // eslint-disable-line require-await
  const key = typeToKey(type)
  if (type.toLowerCase() !== 'ed25519') {
    throw errcode(new Error('Seed key derivation is unimplemented for RSA or secp256k1'), 'ERR_UNSUPPORTED_KEY_DERIVATION_TYPE')
  }

  return key.generateKeyPairFromSeed(seed)
}

/**
 * Converts a protobuf serialized public key into its representative object
 *
 * @param {Uint8Array} buf
 */
const unmarshalPublicKey = (buf) => {
  const decoded = keysPBM.PublicKey.decode(buf)
  const data = decoded.Data

  switch (decoded.Type) {
    case keysPBM.KeyType.RSA:
      return supportedKeys.rsa.unmarshalRsaPublicKey(data)
    case keysPBM.KeyType.Ed25519:
      return supportedKeys.ed25519.unmarshalEd25519PublicKey(data)
    case keysPBM.KeyType.Secp256k1:
      if (supportedKeys.secp256k1) {
        return supportedKeys.secp256k1.unmarshalSecp256k1PublicKey(data)
      } else {
        throw errcode(new Error(ErrMissingSecp256K1.message), ErrMissingSecp256K1.code)
      }
    default:
      throw typeToKey(decoded.Type) // throws because type is not supported
  }
}

/**
 * Converts a public key object into a protobuf serialized public key
 *
 * @template {KeyType} Type
 *
 * @param {import('libp2p-interfaces/src/crypto/types').PublicKey<Type>} key
 * @param {Type} [type='RSA']
 */
const marshalPublicKey = (key, type) => {
  typeToKey(type || 'RSA') // check type
  return key.bytes
}

/**
 * Converts a protobuf serialized private key into its representative object
 *
 * @param {Uint8Array} buf
 */
const unmarshalPrivateKey = async (buf) => { // eslint-disable-line require-await
  const decoded = keysPBM.PrivateKey.decode(buf)
  const data = decoded.Data

  switch (decoded.Type) {
    case keysPBM.KeyType.RSA:
      return supportedKeys.rsa.unmarshalRsaPrivateKey(data)
    case keysPBM.KeyType.Ed25519:
      return supportedKeys.ed25519.unmarshalEd25519PrivateKey(data)
    case keysPBM.KeyType.Secp256k1:
      if (supportedKeys.secp256k1) {
        return supportedKeys.secp256k1.unmarshalSecp256k1PrivateKey(data)
      } else {
        throw errcode(new Error(ErrMissingSecp256K1.message), ErrMissingSecp256K1.code)
      }
    default:
      throw typeToKey(decoded.Type) // throws because type is not supported
  }
}

/**
 * Converts a private key object into a protobuf serialized private key
 *
 * @template {KeyType} Type
 * @param {import('libp2p-interfaces/src/crypto/types').PrivateKey<Type>} key
 * @param {Type} [type='rsa']
 */
const marshalPrivateKey = (key, type) => {
  typeToKey((type || 'RSA')) // check type
  return key.bytes
}

/**
 *
 * @param {string} encryptedKey
 * @param {string} password
 */
const importKey = async (encryptedKey, password) => { // eslint-disable-line require-await
  try {
    const key = await importer.import(encryptedKey, password)
    return unmarshalPrivateKey(key)
  } catch (_) {
    // Ignore and try the old pem decrypt
  }

  // Only rsa supports pem right now
  const key = forge.pki.decryptRsaPrivateKey(encryptedKey, password)
  if (key === null) {
    throw errcode(new Error('Cannot read the key, most likely the password is wrong or not a RSA key'), 'ERR_CANNOT_DECRYPT_PEM')
  }
  const der = forge.asn1.toDer(forge.pki.privateKeyToAsn1(key))
  const derb = uint8ArrayFromString(der.getBytes(), 'ascii')
  return supportedKeys.rsa.unmarshalRsaPrivateKey(derb)
}

module.exports = {
  supportedKeys,
  keysPBM,
  keyStretcher: require('./key-stretcher'),
  generateEphemeralKeyPair: require('./ephemeral-keys'),
  generateKeyPair,
  generateKeyPairFromSeed,
  unmarshalPublicKey,
  marshalPublicKey,
  unmarshalPrivateKey,
  marshalPrivateKey,
  import: importKey
}
