'use strict'

const { Buffer } = require('buffer')
require('node-forge/lib/asn1')
require('node-forge/lib/rsa')
const forge = require('node-forge/lib/forge')
const { bigIntegerToBase64url, base64urlToBigInteger } = require('./../util')

// Convert a PKCS#1 in ASN1 DER format to a JWK key
exports.pkcs1ToJwk = function (bytes) {
  const asn1 = forge.asn1.fromDer(bytes.toString('binary'))
  const privateKey = forge.pki.privateKeyFromAsn1(asn1)

  return {
    kty: 'RSA',
    n: bigIntegerToBase64url(privateKey.n),
    e: bigIntegerToBase64url(privateKey.e),
    d: bigIntegerToBase64url(privateKey.d),
    p: bigIntegerToBase64url(privateKey.p),
    q: bigIntegerToBase64url(privateKey.q),
    dp: bigIntegerToBase64url(privateKey.dP),
    dq: bigIntegerToBase64url(privateKey.dQ),
    qi: bigIntegerToBase64url(privateKey.qInv),
    alg: 'RS256',
    kid: '2011-04-29'
  }
}

// Convert a JWK key into PKCS#1 in ASN1 DER format
exports.jwkToPkcs1 = function (jwk) {
  const asn1 = forge.pki.privateKeyToAsn1({
    n: base64urlToBigInteger(jwk.n),
    e: base64urlToBigInteger(jwk.e),
    d: base64urlToBigInteger(jwk.d),
    p: base64urlToBigInteger(jwk.p),
    q: base64urlToBigInteger(jwk.q),
    dP: base64urlToBigInteger(jwk.dp),
    dQ: base64urlToBigInteger(jwk.dq),
    qInv: base64urlToBigInteger(jwk.qi)
  })

  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary')
}

// Convert a PKCIX in ASN1 DER format to a JWK key
exports.pkixToJwk = function (bytes) {
  const asn1 = forge.asn1.fromDer(bytes.toString('binary'))
  const publicKey = forge.pki.publicKeyFromAsn1(asn1)

  return {
    kty: 'RSA',
    n: bigIntegerToBase64url(publicKey.n),
    e: bigIntegerToBase64url(publicKey.e),
    alg: 'RS256',
    kid: '2011-04-29'
  }
}

// Convert a JWK key to PKCIX in ASN1 DER format
exports.jwkToPkix = function (jwk) {
  const asn1 = forge.pki.publicKeyToAsn1({
    n: base64urlToBigInteger(jwk.n),
    e: base64urlToBigInteger(jwk.e)
  })

  return Buffer.from(forge.asn1.toDer(asn1).getBytes(), 'binary')
}
