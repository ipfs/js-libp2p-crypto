/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
const expect = chai.expect
chai.use(dirtyChai)

const crypto = require('../../src')
const ed25519 = crypto.keys.supportedKeys.ed25519
const fixtures = require('../fixtures/go-key-ed25519')

const testGarbage = require('../helpers/test-garbage-error-handling')

describe('ed25519', function () {
  this.timeout(20 * 1000)
  let key
  before(async () => {
    key = await crypto.keys.generateKeyPair('Ed25519', 512)
  })

  it('generates a valid key', async () => {
    expect(key).to.be.an.instanceof(ed25519.Ed25519PrivateKey)
    const digest = await key.hash()
    expect(digest).to.have.length(34)
  })

  it('generates a valid key from seed', async () => {
    var seed = crypto.randomBytes(32)
    const seededkey = await crypto.keys.generateKeyPairFromSeed('Ed25519', seed, 512)
    expect(seededkey).to.be.an.instanceof(ed25519.Ed25519PrivateKey)
    const digest = await seededkey.hash()
    expect(digest).to.have.length(34)
  })

  it('generates the same key from the same seed', async () => {
    const seed = crypto.randomBytes(32)
    const seededkey1 = await crypto.keys.generateKeyPairFromSeed('Ed25519', seed, 512)
    const seededkey2 = await crypto.keys.generateKeyPairFromSeed('Ed25519', seed, 512)
    expect(seededkey1.equals(seededkey2)).to.eql(true)
    expect(seededkey1.public.equals(seededkey2.public)).to.eql(true)
  })

  it('generates different keys for different seeds', async () => {
    const seed1 = crypto.randomBytes(32)
    const seededkey1 = await crypto.keys.generateKeyPairFromSeed('Ed25519', seed1, 512)
    const seed2 = crypto.randomBytes(32)
    const seededkey2 = await crypto.keys.generateKeyPairFromSeed('Ed25519', seed2, 512)
    expect(seededkey1.equals(seededkey2)).to.eql(false)
    expect(seededkey1.public.equals(seededkey2.public)).to.eql(false)
  })

  it('signs', async () => {
    const text = crypto.randomBytes(512)
    const sig = await key.sign(text)
    const res = await key.public.verify(text, sig)
    expect(res).to.be.eql(true)
  })

  it('encoding', async () => {
    const keyMarshal = key.marshal()
    const key2 = await ed25519.unmarshalEd25519PrivateKey(keyMarshal)
    const keyMarshal2 = key2.marshal()

    expect(keyMarshal).to.eql(keyMarshal2)

    const pk = key.public
    const pkMarshal = pk.marshal()
    const pk2 = ed25519.unmarshalEd25519PublicKey(pkMarshal)
    const pkMarshal2 = pk2.marshal()

    expect(pkMarshal).to.eql(pkMarshal2)
  })

  it('key id', async () => {
    const id = await key.id()
    expect(id).to.exist()
    expect(id).to.be.a('string')
  })

  describe('key equals', () => {
    it('equals itself', () => {
      expect(
        key.equals(key)
      ).to.eql(
        true
      )

      expect(
        key.public.equals(key.public)
      ).to.eql(
        true
      )
    })

    it('not equals other key', async () => {
      const key2 = await crypto.keys.generateKeyPair('Ed25519', 512)
      expect(key.equals(key2)).to.eql(false)
      expect(key2.equals(key)).to.eql(false)
      expect(key.public.equals(key2.public)).to.eql(false)
      expect(key2.public.equals(key.public)).to.eql(false)
    })
  })

  it('sign and verify', async () => {
    const data = Buffer.from('hello world')
    const sig = await key.sign(data)
    const valid = await key.public.verify(data, sig)
    expect(valid).to.eql(true)
  })

  it('fails to verify for different data', async () => {
    const data = Buffer.from('hello world')
    const sig = await key.sign(data)
    const valid = await key.public.verify(Buffer.from('hello'), sig)
    expect(valid).to.be.eql(false)
  })

  describe('returns error via cb instead of crashing', () => {
    const key = crypto.keys.unmarshalPublicKey(fixtures.verify.publicKey)
    testGarbage.doTests('key.verify', key.verify.bind(key), 2)
    testGarbage.doTests('crypto.keys.unmarshalPrivateKey', crypto.keys.unmarshalPrivateKey.bind(crypto.keys))
  })

  describe('go interop', () => {
    let privateKey

    before(async () => {
      const key = await crypto.keys.unmarshalPrivateKey(fixtures.verify.privateKey)
      privateKey = key
    })

    it('verifies with data from go', async () => {
      const key = crypto.keys.unmarshalPublicKey(fixtures.verify.publicKey)
      const ok = await key.verify(fixtures.verify.data, fixtures.verify.signature)
      expect(ok).to.eql(true)
    })

    it('generates the same signature as go', async () => {
      const sig = await privateKey.sign(fixtures.verify.data)
      expect(sig).to.eql(fixtures.verify.signature)
    })
  })
})
