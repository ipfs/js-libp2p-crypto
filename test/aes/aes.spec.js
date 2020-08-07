/* eslint max-nested-callbacks: ["error", 8] */
/* eslint-disable valid-jsdoc */
/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
const expect = chai.expect
chai.use(dirtyChai)
const { expectErrCode } = require('../util')

const crypto = require('../../src')
const fixtures = require('./../fixtures/aes')
const goFixtures = require('./../fixtures/go-aes')

const bytes = {
  16: 'AES-128',
  32: 'AES-256'
}

/** @typedef {import("libp2p-crypto").aes.Cipher} Cipher */

describe('AES-CTR', () => {
  Object.keys(bytes).forEach((byte) => {
    it(`${bytes[byte]} - encrypt and decrypt`, async () => {
      const key = new Uint8Array(parseInt(byte, 10))
      key.fill(5)

      const iv = new Uint8Array(16)
      iv.fill(1)

      const cipher = await crypto.aes.create(key, iv)

      await encryptAndDecrypt(cipher)
      await encryptAndDecrypt(cipher)
      await encryptAndDecrypt(cipher)
      await encryptAndDecrypt(cipher)
      await encryptAndDecrypt(cipher)
    })
  })

  Object.keys(bytes).forEach((byte) => {
    it(`${bytes[byte]} - fixed - encrypt and decrypt`, async () => {
      const key = new Uint8Array(parseInt(byte, 10))
      key.fill(5)

      const iv = new Uint8Array(16)
      iv.fill(1)

      const cipher = await crypto.aes.create(key, iv)

      for (let i = 0; i < fixtures[byte].inputs.length; i++) {
        const rawIn = fixtures[byte].inputs[i]
        const input = Uint8Array.from(rawIn.data)
        const output = Uint8Array.from(fixtures[byte].outputs[i].data)
        const encrypted = await cipher.encrypt(input)
        expect(encrypted).to.have.length(output.length)
        expect(encrypted).to.eql(output)
        const decrypted = await cipher.decrypt(encrypted)
        expect(decrypted).to.eql(input)
      }
    })
  })

  Object.keys(bytes).forEach((byte) => {
    if (!goFixtures[byte]) {
      return
    }

    it(`${bytes[byte]} - go interop - encrypt and decrypt`, async () => {
      const key = new Uint8Array(parseInt(byte, 10))
      key.fill(5)

      const iv = new Uint8Array(16)
      iv.fill(1)

      const cipher = await crypto.aes.create(key, iv)

      for (let i = 0; i < goFixtures[byte].inputs.length; i++) {
        const rawIn = goFixtures[byte].inputs[i]
        const input = Uint8Array.from(rawIn)
        const output = Uint8Array.from(goFixtures[byte].outputs[i])
        const encrypted = await cipher.encrypt(input)
        expect(encrypted).to.have.length(output.length)
        expect(encrypted).to.eql(output)
        const decrypted = await cipher.decrypt(encrypted)
        expect(decrypted).to.eql(input)
      }
    })
  })

  it('checks key length', () => {
    const key = new Uint8Array(5)
    const iv = new Uint8Array(16)
    return expectErrCode(crypto.aes.create(key, iv), 'ERR_INVALID_KEY_LENGTH')
  })
})

// @ts-check
/**
 * @type {function(Cipher): Promise<void>}
 */
async function encryptAndDecrypt (cipher) {
  const data = new Uint8Array(100)
  data.fill(Math.ceil(Math.random() * 100))

  const encrypted = await cipher.encrypt(data)
  const decrypted = await cipher.decrypt(encrypted)

  expect(decrypted).to.be.eql(data)
}
