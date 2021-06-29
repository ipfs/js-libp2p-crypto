'use strict'

// @ts-ignore
require('node-forge/lib/rsa')
// @ts-ignore
const forge = require('node-forge/lib/forge')

const { base64urlToBigInteger } = require('../util')

/**
 * @typedef {import('pem-jwk').RSA_JWK} RSA_JWK
 *
 * @param {*} key
 * @param {string[]} types
 * @returns {any[]}
 */

function convert (key, types) {
  return types.map(t => base64urlToBigInteger(key[t]))
}

/**
 * @param {RSA_JWK} key
 * @returns {import('node-forge').pki.rsa.PrivateKey}
 */
function jwk2priv (key) {
  return forge.pki.setRsaPrivateKey(...convert(key, ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi']))
}

/**
 * @param {RSA_JWK} key
 * @returns {import('node-forge').pki.rsa.PublicKey}
 */
function jwk2pub (key) {
  return forge.pki.setRsaPublicKey(...convert(key, ['n', 'e']))
}

module.exports = {
  jwk2pub,
  jwk2priv
}
