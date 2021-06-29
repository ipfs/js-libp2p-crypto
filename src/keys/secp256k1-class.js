'use strict'

// @ts-ignore
const sha = require('multihashing-async/src/sha')
const errcode = require('err-code')
const uint8ArrayEquals = require('uint8arrays/equals')
const uint8ArrayToString = require('uint8arrays/to-string')

const exporter = require('./exporter')

/**
 * @typedef {ReturnType<import('./secp256k1')>} Secp256k1Crypto
 * @typedef {import('libp2p-interfaces/src/crypto/types').PublicKey<'secp256k1'>} PublicKey
 * @typedef {import('libp2p-interfaces/src/crypto/types').PrivateKey<'secp256k1'>} PrivateKey
 *
 * @typedef {{
 * keysProtobuf: import('./keys')
 * crypto: Secp256k1Crypto
 * }} Context
 */

/**
 * @implements {PublicKey}
 */
class Secp256k1PublicKey {
  /**
   * @param {Context} context
   * @param {Uint8Array} key
   */
  constructor (context, key) {
    /** @private */
    this._context = context
    context.crypto.validatePublicKey(key)
    this._key = key
  }

  /**
   * @type {'secp256k1'}
   */
  get algorithm () {
    return 'secp256k1'
  }

  /**
   * @param {Uint8Array} data
   * @param {Uint8Array} sig
   */
  verify (data, sig) {
    return this._context.crypto.hashAndVerify(this._key, sig, data)
  }

  marshal () {
    return this._context.crypto.compressPublicKey(this._key)
  }

  get bytes () {
    const { keysProtobuf } = this._context
    return keysProtobuf.PublicKey.encode({
      Type: keysProtobuf.KeyType.Secp256k1,
      Data: this.marshal()
    }).finish()
  }

  /**
   *
   * @param {import('libp2p-interfaces/src/crypto/types').PublicKey} key
   * @returns {key is this}
   */
  equals (key) {
    return uint8ArrayEquals(this.bytes, key.bytes)
  }

  hash () {
    return sha.multihashing(this.bytes, 'sha2-256')
  }
}

/**
 * @implements {PrivateKey}
 */
class Secp256k1PrivateKey {
  /**
   * @param {Context} context
   * @param {Uint8Array} key
   * @param {Uint8Array} [publicKey]
   */
  constructor (context, key, publicKey) {
    /** @private */
    this._context = context
    this._key = key
    this._publicKey = publicKey || context.crypto.computePublicKey(key)
    context.crypto.validatePrivateKey(this._key)
    context.crypto.validatePublicKey(this._publicKey)
  }

  /**
   * @type {'secp256k1'}
   */
  get algorithm () {
    return 'secp256k1'
  }

  /**
   * @param {Uint8Array} message
   */

  sign (message) {
    return this._context.crypto.hashAndSign(this._key, message)
  }

  /**
   * @returns {PublicKey}
   */
  get public () {
    return new Secp256k1PublicKey(this._context, this._publicKey)
  }

  marshal () {
    return this._key
  }

  get bytes () {
    const { keysProtobuf } = this._context
    return keysProtobuf.PrivateKey.encode({
      Type: keysProtobuf.KeyType.Secp256k1,
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

  hash () {
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
    const hash = await this.public.hash()
    return uint8ArrayToString(hash, 'base58btc')
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
 * @param {import('./keys')} keysProtobuf
 * @param {import('../random-bytes')} randomBytes
 * @param {ReturnType<import('./secp256k1')>} [cryptoAPI]
 */
module.exports = (keysProtobuf, randomBytes, cryptoAPI) => {
  const crypto = cryptoAPI || require('./secp256k1')(randomBytes)
  const context = { keysProtobuf, crypto }

  /**
   * @param {Uint8Array} bytes
   * @returns {PrivateKey}
   */

  function unmarshalSecp256k1PrivateKey (bytes) {
    return new Secp256k1PrivateKey(context, bytes)
  }

  /**
   *
   * @param {Uint8Array} bytes
   * @returns {PublicKey}
   */
  function unmarshalSecp256k1PublicKey (bytes) {
    return new Secp256k1PublicKey(context, bytes)
  }

  /**
   * @returns {Promise<PrivateKey>}
   */
  async function generateKeyPair () {
    const privateKeyBytes = await crypto.generateKey()
    return new Secp256k1PrivateKey(context, privateKeyBytes)
  }

  return {
    Secp256k1PublicKey,
    Secp256k1PrivateKey,
    unmarshalSecp256k1PrivateKey,
    unmarshalSecp256k1PublicKey,
    generateKeyPair
  }
}
module.exports.Secp256k1PublicKey = Secp256k1PublicKey
module.exports.Secp256k1PrivateKey = Secp256k1PrivateKey
