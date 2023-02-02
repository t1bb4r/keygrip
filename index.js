/*!
 * keygrip
 * Copyright(c) 2011-2014 Jed Schmidt
 * MIT Licensed
 */

'use strict'

var compare = require('tsscmp')
var crypto = require("crypto")
  
function Keygrip(keys, algorithm, encoding, keyEncoding) {
  if (!algorithm) algorithm = "sha1";
  if (!encoding) encoding = "base64";
  if (!(this instanceof Keygrip)) return new Keygrip(keys, algorithm, encoding, keyEncoding)

  if (!keys || !(0 in keys)) {
    throw new Error("Keys must be provided.")
  }

  function sign(data, key) {
    var chain = crypto;
    if (keyEncoding) {
      chain = chain.createHmac(algorithm, key, {encoding: keyEncoding});
    } else {
      chain = chain.createHmac(algorithm, key);
    }
    chain = chain.update(data).digest(encoding)
    if (encoding === "base64") {
      return chain
      .replace(/\/|\+|=/g, function(x) {
        return ({ "/": "_", "+": "-", "=": "" })[x]
      })
    }
    return chain;
  }

  this.sign = function(data){ return sign(data, keys[0]) }

  this.verify = function(data, digest) {
    return this.index(data, digest) > -1
  }

  this.index = function(data, digest) {
    for (var i = 0, l = keys.length; i < l; i++) {
      if (compare(digest, sign(data, keys[i]))) {
        return i
      }
    }

    return -1
  }
}

Keygrip.sign = Keygrip.verify = Keygrip.index = function() {
  throw new Error("Usage: require('keygrip')(<array-of-keys>)")
}

module.exports = Keygrip
