'use strict';

var _ = require('lodash');
var BN = require('../crypto/bn');
var buffer = require('buffer');
var bufferUtil = require('../util/buffer');
var JSUtil = require('../util/js');
var BufferWriter = require('../encoding/bufferwriter');
var BufferReader = require('../encoding/bufferreader');
var Script = require('../script');
var $ = require('../util/preconditions');
var errors = require('../errors');
var blsct = require('../crypto/blsct');

var MAX_SAFE_INTEGER = 0x1fffffffffffff;

function Output(args) {
  if (!(this instanceof Output)) {
    return new Output(args);
  }
  if (_.isObject(args)) {
    this.satoshis = args.satoshis;
    this.ok = new blsct.mcl.G1();
    let isZero = (el) => {
      if (!el || el.length == 0)
        return true;
      for (var i in el)
      {
        if (el[1] != 0x0)
          return false;
      }
      return true;
    }

    if (args.ok && !isZero(args.ok))
    {
      this.ok.deserialize(new Uint8Array(args.ok));
    }
    this.ek = new blsct.mcl.G1();
    if (args.ek && !isZero(args.ek))
    {
      this.ek.deserialize(args.ek);
    }
    this.sk = new blsct.mcl.G1();
    if (args.sk && !isZero(args.sk))
    {
      this.sk.deserialize(args.sk);
    }

    this.bp = {
      V: [],
      L: [],
      R: [],
      A: new blsct.mcl.G1(),
      S: new blsct.mcl.G1(),
      T1: new blsct.mcl.G1(),
      T2: new blsct.mcl.G1(),
      taux: new blsct.mcl.Fr(),
      a: new blsct.mcl.Fr(),
      b: new blsct.mcl.Fr(),
      t: new blsct.mcl.Fr(),
      mu: new blsct.mcl.Fr(),
    };

    if (args.bp)
    {
      for (var i in args.bp.V)
      {
        this.bp.V.push(new blsct.mcl.G1())
        this.bp.V[i].deserialize(args.bp.V[i])
      }

      for (var i in args.bp.L)
      {
        this.bp.L.push(new blsct.mcl.G1())
        this.bp.L[i].deserialize(args.bp.L[i])
      }

      for (var i in args.bp.R)
      {
        this.bp.R.push(new blsct.mcl.G1())
        this.bp.R[i].deserialize(args.bp.R[i])
      }

      this.bp.A.deserialize(args.bp.A)
      this.bp.S.deserialize(args.bp.S)
      this.bp.T1.deserialize(args.bp.T1)
      this.bp.T2.deserialize(args.bp.T2)

      this.bp.taux.deserialize(args.bp.taux)
      this.bp.mu.deserialize(args.bp.mu)
      this.bp.a.deserialize(args.bp.a)
      this.bp.b.deserialize(args.bp.b)
      this.bp.t.deserialize(args.bp.t)
    }

    if (bufferUtil.isBuffer(args.script)) {
      this._scriptBuffer = args.script;
    } else {
      var script;
      if (_.isString(args.script) && JSUtil.isHexa(args.script)) {
        script = new buffer.Buffer(args.script, 'hex');
      } else {
        script = args.script;
      }
      this.setScript(script);
    }
  } else {
    throw new TypeError('Unrecognized argument for Output');
  }
}


Object.defineProperty(Output.prototype, 'script', {
  configurable: false,
  enumerable: true,
  get: function() {
    if (this._script) {
      return this._script;
    } else {
      this.setScriptFromBuffer(this._scriptBuffer);
      return this._script;
    }
  }
});

Object.defineProperty(Output.prototype, 'satoshis', {
  configurable: false,
  enumerable: true,
  get: function() {
    return this._satoshis;
  },
  set: function(num) {
    if (num instanceof BN) {
      this._satoshisBN = num;
      this._satoshis = num.toNumber();
    } else if (_.isString(num)) {
      this._satoshis = parseInt(num);
      this._satoshisBN = BN.fromNumber(this._satoshis);
    } else {
      $.checkArgument(
          JSUtil.isNaturalNumber(num),
          'Output satoshis is not a natural number'
      );
      this._satoshisBN = BN.fromNumber(num);
      this._satoshis = num;
    }
    $.checkState(
        JSUtil.isNaturalNumber(this._satoshis),
        'Output satoshis is not a natural number'
    );
  }
});

Output.prototype.invalidSatoshis = function() {
  if (this._satoshis > MAX_SAFE_INTEGER) {
    return 'transaction txout satoshis greater than max safe integer';
  }
  if (this._satoshis !== this._satoshisBN.toNumber()) {
    return 'transaction txout satoshis has corrupted value';
  }
  if (this._satoshis < 0) {
    return 'transaction txout negative';
  }
  return false;
};

Output.prototype.isCt = function () {
  return (this.bp && this.bp.V && this.bp.V.length);
}

Output.prototype.hasBlsctKeys = function () {
  return (this.ek && !this.ek.isZero()) || (this.ok && !this.ok.isZero()) || (this.sk && !this.sk.isZero());
}

Output.prototype.toObject = Output.prototype.toJSON = function toObject() {
  var obj = {
    satoshis: this.satoshis
  };
  obj.script = this._scriptBuffer.toString('hex');
  if (this.bp && this.bp.V && this.bp.V.length)
  {
    obj.bp = {
      V: [],
      L: [],
      R: [],
      A: (new blsct.mcl.G1()).serialize(),
      S: (new blsct.mcl.G1()).serialize(),
      T1: (new blsct.mcl.G1()).serialize(),
      T2: (new blsct.mcl.G1()).serialize(),
      taux: (new blsct.mcl.Fr()).serialize(),
      a: (new blsct.mcl.Fr()).serialize(),
      b: (new blsct.mcl.Fr()).serialize(),
      t: (new blsct.mcl.Fr()).serialize(),
      mu: (new blsct.mcl.Fr()).serialize(),
    };
    if (this.bp)
    {
      if (this.bp.V)
      {
        for (var i in this.bp.V)
        {
          obj.bp.V.push(this.bp.V[i].serialize())
        }
        for (var i in this.bp.L)
        {
          obj.bp.L.push(this.bp.L[i].serialize())
        }
        for (var i in this.bp.R)
        {
          obj.bp.V.push(this.bp.R[i].serialize())
        }
      }
      if (this.bp.A)
        obj.bp.A = this.bp.A.serialize();
      if (this.bp.S)
        obj.bp.S = this.bp.S.serialize();
      if (this.bp.T1)
        obj.bp.T1 = this.bp.T1.serialize();
      if (this.bp.T2)
        obj.bp.T2 = this.bp.T2.serialize();
      if (this.bp.taux)
        obj.bp.taux = this.bp.taux.serialize();
      if (this.bp.mu)
        obj.bp.mu = this.bp.mu.serialize();
      if (this.bp.a)
        obj.bp.a = this.bp.a.serialize();
      if (this.bp.b)
        obj.bp.b = this.bp.b.serialize();
      if (this.bp.t)
        obj.bp.t = this.bp.t.serialize();

    }
    obj.ek = this.ek ? this.ek.serialize() : new mcl.G1();
    obj.ok = this.ok ? this.ok.serialize() : new mcl.G1();
    obj.sk = this.sk ? this.sk.serialize() : new mcl.G1();
  }
  return obj;
};

Output.fromObject = function(data) {
  return new Output(data);
};

Output.prototype.setScriptFromBuffer = function(buffer) {
  this._scriptBuffer = buffer;
  try {
    this._script = Script.fromBuffer(this._scriptBuffer);
    this._script._isOutput = true;
  } catch(e) {
    if (e instanceof errors.Script.InvalidBuffer) {
      this._script = null;
    } else {
      throw e;
    }
  }
};

Output.prototype.setScript = function(script) {
  if (script instanceof Script) {
    this._scriptBuffer = script.toBuffer();
    this._script = script;
    this._script._isOutput = true;
  } else if (_.isString(script)) {
    this._script = Script.fromString(script);
    this._scriptBuffer = this._script.toBuffer();
    this._script._isOutput = true;
  } else if (bufferUtil.isBuffer(script)) {
    this.setScriptFromBuffer(script);
  } else {
    throw new TypeError('Invalid argument type: script');
  }
  return this;
};

Output.prototype.inspect = function() {
  var scriptStr;
  if (this.script) {
    scriptStr = this.script.inspect();
  } else {
    scriptStr = this._scriptBuffer.toString('hex');
  }
  return '<Output (' + this.satoshis + ' sats) ' + scriptStr + '>';
};

Output.fromBufferReader = function(br) {
  var obj = {};
  obj.satoshis = br.readUInt64LEBN();
  if (obj.satoshis == 0xFFFFFFFFFFFFFFFF)
  {
    obj.satoshis = br.readUInt64LEBN();

    obj.ek = blsct.DeserializeG1(br)
    obj.ok = blsct.DeserializeG1(br)
    obj.sk = blsct.DeserializeG1(br)
    obj.bp = blsct.DeserializeProof(br);
  }
  var size = br.readVarintNum();
  if (size !== 0) {
    obj.script = br.read(size);
  } else {
    obj.script = new buffer.Buffer([]);
  }
  return new Output(obj);
};


Output.prototype.fromBuffer = function(buffer) {
  var reader = new BufferReader(buffer);
  return this.fromBufferReader(reader);
};

Output.prototype.toBufferWriter = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  if ((!this.ek.isZero()) || (!this.ok.isZero()) || (!this.sk.isZero())) {
    writer.write(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]));
    writer.writeUInt64LEBN(this._satoshisBN);
    blsct.SerializeG1(writer, this.ek);
    blsct.SerializeG1(writer, this.ok);
    blsct.SerializeG1(writer, this.sk);
    blsct.SerializeProof(writer, this.bp);
  } else {
    writer.writeUInt64LEBN(this._satoshisBN);
  }
  var script = this._scriptBuffer;
  writer.writeVarintNum(script.length);
  writer.write(script);
  return writer;
};

module.exports = Output;
