'use strict'

// @ts-ignore
require('node-forge/lib/asn1')
// @ts-ignore
require('node-forge/lib/rsa')
/** @type {import('node-forge')} */
// @ts-ignore
const forge = require('node-forge/lib/forge')
const { bigIntegerToUintBase64url, base64urlToBigInteger } = require('./../util')
const uint8ArrayFromString = require('uint8arrays/from-string')
const uint8ArrayToString = require('uint8arrays/to-string')

/**
 * Convert a PKCS#1 in ASN1 DER format to a JWK key
 *
 * @param {Uint8Array} bytes
 */
exports.pkcs1ToJwk = function (bytes) {
  const asn1 = forge.asn1.fromDer(uint8ArrayToString(bytes, 'ascii'))
  const privateKey = /** @type {import('node-forge').pki.rsa.PrivateKey} */
    (forge.pki.privateKeyFromAsn1(asn1))

  // https://tools.ietf.org/html/rfc7518#section-6.3.1
  return {
    kty: 'RSA',
    n: bigIntegerToUintBase64url(privateKey.n),
    e: bigIntegerToUintBase64url(privateKey.e),
    d: bigIntegerToUintBase64url(privateKey.d),
    p: bigIntegerToUintBase64url(privateKey.p),
    q: bigIntegerToUintBase64url(privateKey.q),
    dp: bigIntegerToUintBase64url(privateKey.dP),
    dq: bigIntegerToUintBase64url(privateKey.dQ),
    qi: bigIntegerToUintBase64url(privateKey.qInv),
    alg: 'RS256',
    kid: '2011-04-29'
  }
}

/**
 * Convert a JWK key into PKCS#1 in ASN1 DER format
 *
 * @param {import('pem-jwk').RSA_JWK} jwk
 */
exports.jwkToPkcs1 = function (jwk) {
  // @ts-ignore - struct isn't PrivateKey
  const asn1 = forge.pki.privateKeyToAsn1({
    n: base64urlToBigInteger(jwk.n),
    e: base64urlToBigInteger(jwk.e),
    // @ts-ignore - d is optional
    d: base64urlToBigInteger(jwk.d),
    // @ts-ignore - p is optional
    p: base64urlToBigInteger(jwk.p),
    // @ts-ignore - q is optional
    q: base64urlToBigInteger(jwk.q),
    // @ts-ignore - dp is optional
    dP: base64urlToBigInteger(jwk.dp),
    // @ts-ignore - dq is optional
    dQ: base64urlToBigInteger(jwk.dq),
    // @ts-ignore - qi is optional
    qInv: base64urlToBigInteger(jwk.qi)
  })

  return uint8ArrayFromString(forge.asn1.toDer(asn1).getBytes(), 'ascii')
}

/**
 * Convert a PKCIX in ASN1 DER format to a JWK key
 *
 * @param {Uint8Array} bytes
 */
exports.pkixToJwk = function (bytes) {
  const asn1 = forge.asn1.fromDer(uint8ArrayToString(bytes, 'ascii'))
  const publicKey = /** @type {import('node-forge').pki.rsa.PublicKey} */
    (forge.pki.publicKeyFromAsn1(asn1))

  return {
    kty: 'RSA',
    n: bigIntegerToUintBase64url(publicKey.n),
    e: bigIntegerToUintBase64url(publicKey.e),
    alg: 'RS256',
    kid: '2011-04-29'
  }
}

/**
 * Convert a JWK key to PKCIX in ASN1 DER format
 *
 * @param {import('pem-jwk').RSA_JWK} jwk
 */
exports.jwkToPkix = function (jwk) {
  // @ts-expect-error - public key has more stuff
  const asn1 = forge.pki.publicKeyToAsn1({
    n: base64urlToBigInteger(jwk.n),
    e: base64urlToBigInteger(jwk.e)
  })

  return uint8ArrayFromString(forge.asn1.toDer(asn1).getBytes(), 'ascii')
}
