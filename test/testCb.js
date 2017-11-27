/* eslint-env mocha */
'use strict'

const chai = require('chai')
const dirtyChai = require('dirty-chai')
const expect = chai.expect
chai.use(dirtyChai)

const util = require('util')
const garbage = [Buffer.from('00010203040506070809', 'hex'), {}, null, false, undefined, true, 1, 0, Buffer.from(''), 'aGVsbG93b3JsZA==', 'helloworld', '']

function doTests (fncName, fnc, num) {
  if (!num) {
    num = 1
  }

  garbage.forEach(garbage => {
    let args = []
    for (let i = 0; i < num; i++) {
      args.push(garbage)
    }
    it(fncName + '(' + args.map(garbage => util.inspect(garbage)).join(', ') + ')', cb => {
      args.push((err, res) => {
        expect(err).to.exist()
        expect(res).to.not.exist()
        cb()
      })

      fnc(...args)
    })
  })
}

module.exports = (obj, fncs, num) => {
  describe('returns error via cb instead of crashing', () => {
    fncs.forEach(fnc => {
      doTests(fnc, obj[fnc], num)
    })
  })
}

module.exports.doTests = doTests
