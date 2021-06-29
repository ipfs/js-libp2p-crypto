'use strict'

// @ts-ignore
const sha = require('multihashing-async/src/sha')
const errcode = require('err-code')
const uint8ArrayEquals = require('uint8arrays/equals')
const mh = require('multihashes')
const crypto = require('./ed25519')
const pbm = require('./keys')
const exporter = require('./exporter')

/**
 * @typedef {import('libp2p-interfaces/src/crypto/types').PublicKey<'Ed25519'>} PublicKey
 * @implements {PublicKey}
 */
class Ed25519PublicKey {
  /**
   * @param {Uint8Array} key
   */
  constructor (key) {
    /** @private */
    this._key = ensureKey(key, crypto.publicKeyLength)
  }

  /**
   * @type {'Ed25519'}
   */
  get algorithm () {
    return 'Ed25519'
  }

  /**
   *
   * @param {Uint8Array} data
   * @param {Uint8Array} sig
   */
  async verify (data, sig) { // eslint-disable-line require-await
    return crypto.hashAndVerify(this._key, sig, data)
  }

  marshal () {
    return this._key
  }

  get bytes () {
    return pbm.PublicKey.encode({
      Type: pbm.KeyType.Ed25519,
      Data: this.marshal()
    }).finish()
  }

  /**
   * @param {import('libp2p-interfaces/src/crypto/types').PublicKey} key
   * @returns {key is this}
   */
  equals (key) {
    return uint8ArrayEquals(this.bytes, key.bytes)
  }

  async hash () { // eslint-disable-line require-await
    return sha.multihashing(this.bytes, 'sha2-256')
  }
}

/**
 * @typedef {import('libp2p-interfaces/src/crypto/types').PrivateKey<'Ed25519'>} PrivateKey
 * @implements {PrivateKey}
 */
class Ed25519PrivateKey {
  /**
   *
   * @param {Uint8Array} key - 64 byte Uint8Array containing private key
   * @param {Uint8Array} publicKey - 32 byte Uint8Array containing public key
   */
  constructor (key, publicKey) {
    /** @private */
    this._key = ensureKey(key, crypto.privateKeyLength)
    /** @private */
    this._publicKey = ensureKey(publicKey, crypto.publicKeyLength)
  }

  /**
   * @type {'Ed25519'}
   */
  get algorithm () {
    return 'Ed25519'
  }

  /**
   * @param {Uint8Array} message
   */
  async sign (message) { // eslint-disable-line require-await
    return crypto.hashAndSign(this._key, message)
  }

  get public () {
    return new Ed25519PublicKey(this._publicKey)
  }

  marshal () {
    return this._key
  }

  get bytes () {
    return pbm.PrivateKey.encode({
      Type: pbm.KeyType.Ed25519,
      Data: this.marshal()
    }).finish()
  }

  /**
   * @param {import('libp2p-interfaces/src/crypto/types').PrivateKey} key
   * @returns {key is this}
   */
  equals (key) {
    return uint8ArrayEquals(this.bytes, key.bytes)
  }

  async hash () { // eslint-disable-line require-await
    return sha.multihashing(this.bytes, 'sha2-256')
  }

  /**
   * Gets the ID of the key.
   *
   * The key id is the base58 encoding of the SHA-256 multihash of its public key.
   * The public key is a protobuf encoding containing a type and the DER encoding
   * of the PKCS SubjectPublicKeyInfo.
   *
   * @returns {Promise<string>}
   */
  async id () {
    const encoding = mh.encode(this.public.bytes, 'identity')
    return await mh.toB58String(encoding)
  }

  /**
   * Exports the key into a password protected `format`
   *
   * @param {string} password - The password to encrypt the key
   * @param {string} [format=libp2p-key] - The format in which to export as
   * @returns {Promise<string>} The encrypted private key
   */
  async export (password, format = 'libp2p-key') { // eslint-disable-line require-await
    if (format === 'libp2p-key') {
      return exporter.export(this.bytes, password)
    } else {
      throw errcode(new Error(`export format '${format}' is not supported`), 'ERR_INVALID_EXPORT_FORMAT')
    }
  }
}

/**
 * @param {Uint8Array} bytes
 * @returns {PrivateKey}
 */
function unmarshalEd25519PrivateKey (bytes) {
  // Try the old, redundant public key version
  if (bytes.length > crypto.privateKeyLength) {
    bytes = ensureKey(bytes, crypto.privateKeyLength + crypto.publicKeyLength)
    const privateKeyBytes = bytes.slice(0, crypto.privateKeyLength)
    const publicKeyBytes = bytes.slice(crypto.privateKeyLength, bytes.length)
    return new Ed25519PrivateKey(privateKeyBytes, publicKeyBytes)
  }

  bytes = ensureKey(bytes, crypto.privateKeyLength)
  const privateKeyBytes = bytes.slice(0, crypto.privateKeyLength)
  const publicKeyBytes = bytes.slice(crypto.publicKeyLength)
  return new Ed25519PrivateKey(privateKeyBytes, publicKeyBytes)
}

/**
 * @param {Uint8Array} bytes
 * @returns {PublicKey}
 */
function unmarshalEd25519PublicKey (bytes) {
  bytes = ensureKey(bytes, crypto.publicKeyLength)
  return new Ed25519PublicKey(bytes)
}

/**
 * @returns {Promise<PrivateKey>}
 */
async function generateKeyPair () {
  const { privateKey, publicKey } = await crypto.generateKey()
  return new Ed25519PrivateKey(privateKey, publicKey)
}

/**
 *
 * @param {Uint8Array} seed
 * @returns {Promise<PrivateKey>}
 */
async function generateKeyPairFromSeed (seed) {
  const { privateKey, publicKey } = await crypto.generateKeyFromSeed(seed)
  return new Ed25519PrivateKey(privateKey, publicKey)
}

/**
 *
 * @param {Uint8Array} key
 * @param {number} length
 */
function ensureKey (key, length) {
  key = Uint8Array.from(key || [])
  if (key.length !== length) {
    throw errcode(new Error(`Key must be a Uint8Array of length ${length}, got ${key.length}`), 'ERR_INVALID_KEY_TYPE')
  }
  return key
}

module.exports = {
  Ed25519PublicKey,
  Ed25519PrivateKey,
  unmarshalEd25519PrivateKey,
  unmarshalEd25519PublicKey,
  generateKeyPair,
  generateKeyPairFromSeed
}
