'use strict'

const hmac = require('./hmac')
const aes = require('./aes')
const keys = require('./keys')

/**
 * Maps an IPFS hash name to its node-forge equivalent.
 * See https://github.com/multiformats/multihash/blob/master/hashtable.csv
 *
 * @typedef {import('./hmac').HashType} HashType
 * @typedef {import('./keys/ecdh').Curve} CurveType
 * @typedef {import('./keys/key-stretcher').Cipher} CipherType
 */

/**
 * Exposes an interface to AES encryption (formerly Rijndael),
 * as defined in U.S. Federal Information Processing Standards Publication 197.
 * This uses CTR mode.
 */
exports.aes = aes

/**
 * Exposes an interface to the Keyed-Hash Message Authentication Code (HMAC)
 * as defined in U.S. Federal Information Processing Standards Publication 198.
 * An HMAC is a cryptographic hash that uses a key to sign a message.
 * The receiver verifies the hash by recomputing it using the same key.
 */
exports.hmac = hmac

/**
 * Exposes an interface to various cryptographic key generation routines.
 * Currently the 'RSA' and 'ed25519' types are supported, although ed25519 keys
 * support only signing and verification of messages. For encryption / decryption
 * support, RSA keys should be used.
 * Installing the libp2p-crypto-secp256k1 module adds support for the 'secp256k1'
 * type, which supports ECDSA signatures using the secp256k1 elliptic curve
 * popularized by Bitcoin. This module is not installed by default, and should be
 * explicitly depended on if your project requires secp256k1 support.
 */
exports.keys = keys
exports.randomBytes = require('./random-bytes')
exports.pbkdf2 = require('./pbkdf2')
