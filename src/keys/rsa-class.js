'use strict'

// @ts-ignore
const sha = require('multihashing-async/src/sha')
const errcode = require('err-code')
const uint8ArrayEquals = require('uint8arrays/equals')
const uint8ArrayToString = require('uint8arrays/to-string')

// @ts-ignore
require('node-forge/lib/sha512')
// @ts-ignore
require('node-forge/lib/ed25519')
/** @type {import('node-forge')} */
// @ts-ignore
const forge = require('node-forge/lib/forge')

const crypto = require('./rsa')
const pbm = require('./keys')
const exporter = require('./exporter')

/**
 * @typedef {import('libp2p-interfaces/src/crypto/types').PublicKey<'RSA'>} VerificationKey
 * @typedef {import('libp2p-interfaces/src/crypto/types').EncryptionKey} EncryptionKey
 * @typedef {import('libp2p-interfaces/src/crypto/types').PrivateKey<'RSA'>} SigningKey
 * @typedef {import('libp2p-interfaces/src/crypto/types').DecryptionKey} DecryptionKey
 * @typedef {VerificationKey & EncryptionKey} PublicKey
 * @typedef {SigningKey & DecryptionKey & { public: PublicKey }} PrivateKey
 * @typedef {import('pem-jwk').RSA_JWK} JWK
 *
 * @implements {VerificationKey}
 * @implements {EncryptionKey}
 */
class RsaPublicKey {
  /**
   @param {JWK} key - Public key in JWK format
   */
  constructor (key) {
    this._key = key
  }

  /**
   * @returns {'RSA'}
   */
  get algorithm () {
    return 'RSA'
  }

  // @ts-ignore
  async verify (data, sig) { // eslint-disable-line require-await
    return crypto.hashAndVerify(this._key, sig, data)
  }

  marshal () {
    return crypto.utils.jwkToPkix(this._key)
  }

  get bytes () {
    return pbm.PublicKey.encode({
      Type: pbm.KeyType.RSA,
      Data: this.marshal()
    }).finish()
  }

  /**
   * @param {Uint8Array} bytes
   */

  encrypt (bytes) {
    return crypto.encrypt(this._key, bytes)
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
 * @implements {SigningKey}
 * @implements {DecryptionKey}
 */
class RsaPrivateKey {
  /**
   * @param {JWK} key - Private key in JWT format
   * @param {JWK} publicKey - Public key in JWT format
   */
  constructor (key, publicKey) {
    this._key = key
    this._publicKey = publicKey
  }

  /**
   * @type {'RSA'}
   */
  get algorithm () {
    return 'RSA'
  }

  genSecret () {
    return crypto.getRandomValues(16)
  }

  // @ts-ignore
  async sign (message) { // eslint-disable-line require-await
    return crypto.hashAndSign(this._key, message)
  }

  get public () {
    if (!this._publicKey) {
      throw errcode(new Error('public key not provided'), 'ERR_PUBKEY_NOT_PROVIDED')
    }

    return new RsaPublicKey(this._publicKey)
  }

  // @ts-ignore
  decrypt (bytes) {
    return crypto.decrypt(this._key, bytes)
  }

  marshal () {
    return crypto.utils.jwkToPkcs1(this._key)
  }

  get bytes () {
    return pbm.PrivateKey.encode({
      Type: pbm.KeyType.RSA,
      Data: this.marshal()
    }).finish()
  }

  /**
   *
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
    const hash = await this.public.hash()
    return uint8ArrayToString(hash, 'base58btc')
  }

  /**
   * Exports the key into a password protected PEM format
   *
   * @param {string} password - The password to read the encrypted PEM
   * @param {string} [format=pkcs-8] - The format in which to export as
   */
  async export (password, format = 'pkcs-8') { // eslint-disable-line require-await
    if (format === 'pkcs-8') {
      // @ts-ignore - ByteBuffer isn't present in typedefs
      const buffer = new forge.util.ByteBuffer(this.marshal())
      const asn1 = forge.asn1.fromDer(buffer)
      const privateKey = forge.pki.privateKeyFromAsn1(asn1)

      return forge.pki.encryptRsaPrivateKey(privateKey, password, {
        algorithm: 'aes256',
        count: 10000,
        saltSize: 128 / 8,
        prfAlgorithm: 'sha512'
      })
    } else if (format === 'libp2p-key') {
      return exporter.export(this.bytes, password)
    } else {
      throw errcode(new Error(`export format '${format}' is not supported`), 'ERR_INVALID_EXPORT_FORMAT')
    }
  }
}

/**
 *
 * @param {Uint8Array} bytes
 * @returns {Promise<PrivateKey>}
 */
async function unmarshalRsaPrivateKey (bytes) {
  const jwk = crypto.utils.pkcs1ToJwk(bytes)
  const keys = await crypto.unmarshalPrivateKey(jwk)
  return new RsaPrivateKey(keys.privateKey, keys.publicKey)
}

/**
 * @param {Uint8Array} bytes
 * @returns {PublicKey}
 */
function unmarshalRsaPublicKey (bytes) {
  const jwk = crypto.utils.pkixToJwk(bytes)
  return new RsaPublicKey(jwk)
}

/**
 *
 * @param {JWK} jwk
 * @returns {Promise<PrivateKey>}
 */
async function fromJwk (jwk) {
  const keys = await crypto.unmarshalPrivateKey(jwk)
  return new RsaPrivateKey(keys.privateKey, keys.publicKey)
}

/**
 *
 * @param {number} bits
 * @returns {Promise<PrivateKey>}
 */
async function generateKeyPair (bits) {
  const keys = await crypto.generateKey(bits)
  return new RsaPrivateKey(keys.privateKey, keys.publicKey)
}

const genSecret = () => crypto.getRandomValues(16)

module.exports = {
  RsaPublicKey,
  RsaPrivateKey,
  unmarshalRsaPublicKey,
  unmarshalRsaPrivateKey,
  generateKeyPair,
  fromJwk,
  genSecret
}
