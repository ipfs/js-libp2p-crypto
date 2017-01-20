/* eslint-env mocha */
'use strict'

const expect = require('chai').expect
const Buffer = require('safe-buffer').Buffer

describe('with libp2p-crypto-secp256k1 module present', () => {
  const crypto = require('../src')
  const secp256k1 = crypto.keys.secp256k1
  let key

  before((done) => {
    expect(secp256k1).to.exist
    crypto.generateKeyPair('secp256k1', 256, (err, _key) => {
      if (err) return done(err)
      key = _key
      done()
    })
  })

  it('generates a valid key', (done) => {
    expect(
      key
    ).to.be.an.instanceof(
      secp256k1.Secp256k1PrivateKey
    )

    key.hash((err, digest) => {
      if (err) {
        return done(err)
      }

      expect(digest).to.have.length(34)
      done()
    })
  })

  it('signs', (done) => {
    const text = crypto.randomBytes(512)

    key.sign(text, (err, sig) => {
      if (err) {
        return done(err)
      }

      key.public.verify(text, sig, (err, res) => {
        if (err) {
          return done(err)
        }

        expect(res).to.be.eql(true)
        done()
      })
    })
  })

  it('encoding', (done) => {
    const keyMarshal = key.marshal()
    secp256k1.unmarshalSecp256k1PrivateKey(keyMarshal, (err, key2) => {
      if (err) {
        return done(err)
      }
      const keyMarshal2 = key2.marshal()

      expect(
        keyMarshal
      ).to.be.eql(
        keyMarshal2
      )

      const pk = key.public
      const pkMarshal = pk.marshal()
      const pk2 = secp256k1.unmarshalSecp256k1PublicKey(pkMarshal)
      const pkMarshal2 = pk2.marshal()

      expect(
        pkMarshal
      ).to.be.eql(
        pkMarshal2
      )
      done()
    })
  })

  it('protobuf encoding', (done) => {
    const keyMarshal = crypto.marshalPrivateKey(key)
    crypto.unmarshalPrivateKey(keyMarshal, (err, key2) => {
      if (err) return done(err)
      const keyMarshal2 = crypto.marshalPrivateKey(key2)

      expect(
        keyMarshal
      ).to.be.eql(
        keyMarshal2
      )

      const pk = key.public
      const pkMarshal = crypto.marshalPublicKey(pk)
      const pk2 = crypto.unmarshalPublicKey(pkMarshal)
      const pkMarshal2 = crypto.marshalPublicKey(pk2)

      expect(
        pkMarshal
      ).to.be.eql(
        pkMarshal2
      )
      done()
    })
  })

  describe('key equals', () => {
    it('equals itself', () => {
      expect(
        key.equals(key)
      ).to.be.eql(
        true
      )

      expect(
        key.public.equals(key.public)
      ).to.be.eql(
        true
      )
    })

    it('not equals other key', (done) => {
      crypto.generateKeyPair('secp256k1', 256, (err, key2) => {
        if (err) return done(err)

        expect(
          key.equals(key2)
        ).to.be.eql(
          false
        )

        expect(
          key2.equals(key)
        ).to.be.eql(
          false
        )

        expect(
          key.public.equals(key2.public)
        ).to.be.eql(
          false
        )

        expect(
          key2.public.equals(key.public)
        ).to.be.eql(
          false
        )
        done()
      })
    })
  })

  it('sign and verify', (done) => {
    const data = Buffer.from('hello world')
    key.sign(data, (err, sig) => {
      if (err) {
        return done(err)
      }

      key.public.verify(data, sig, (err, valid) => {
        if (err) {
          return done(err)
        }
        expect(valid).to.be.eql(true)
        done()
      })
    })
  })

  it('fails to verify for different data', (done) => {
    const data = Buffer.from('hello world')
    key.sign(data, (err, sig) => {
      if (err) {
        return done(err)
      }

      key.public.verify(Buffer.from('hello'), sig, (err, valid) => {
        if (err) {
          return done(err)
        }
        expect(valid).to.be.eql(false)
        done()
      })
    })
  })
})

describe('without libp2p-crypto-secp256k1 module present', () => {
  const crypto = require('../src')
  const fixtures = require('./fixtures/secp256k1')

  // remove the 'secp256k1' field from libp2p-crypto.keys and replace it after tests are run
  // this simulates a failure to load the libp2p-crypto-secp256k1 module.
  let secp256k1
  before(() => {
    secp256k1 = crypto.keys.secp256k1
    delete crypto.keys['secp256k1']
  })

  after(() => {
    crypto.keys['secp256k1'] = secp256k1
  })

  it('fails to generate a secp256k1 key', (done) => {
    crypto.generateKeyPair('secp256k1', 256, (err, key) => {
      expect(err).to.exist
      expect(key).to.not.exist
      done()
    })
  })

  it('fails to unmarshal a secp256k1 private key', (done) => {
    crypto.unmarshalPrivateKey(fixtures.pbmPrivateKey, (err, key) => {
      expect(err).to.exist
      expect(key).to.not.exist
      done()
    })
  })

  it('fails to unmarshal a secp256k1 public key', () => {
    expect(() => {
      crypto.unmarshalPublicKey(fixtures.pbmPublicKey)
    }).to.throw(Error)
  })
})