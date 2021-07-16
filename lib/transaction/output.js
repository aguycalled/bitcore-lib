'use strict';

var _ = require('lodash');
var BN = require('../crypto/bn');
var buffer = require('buffer');
var bufferUtil = require('../util/buffer');
var JSUtil = require('../util/js');
var BufferWriter = require('../encoding/bufferwriter');
var Script = require('../script');
var $ = require('../util/preconditions');
var errors = require('../errors');
var blsct = import('./blsct');

var MAX_SAFE_INTEGER = 0x1fffffffffffff;

function Output(args) {
  if (!(this instanceof Output)) {
    return new Output(args);
  }
  if (_.isObject(args)) {
    this.satoshis = args.satoshis;
    this.ok = args.ok;
    this.ek = args.ek;
    this.sk = args.sk;
    this.bp = args.bp;
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

Output.prototype.toObject = Output.prototype.toJSON = function toObject() {
  var obj = {
    satoshis: this.satoshis
  };
  obj.script = this._scriptBuffer.toString('hex');
  obj.bp = this.bp;
  obj.ek = this.ek;
  obj.ok = this.ok;
  obj.sk = this.sk;
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

    var size = br.readVarintNum();
    obj.ek = new blsct.mcl.G1();
    obj.ek.deserialize(br.read(size));

    var size = br.readVarintNum();
    obj.ok = new blsct.mcl.G1();
    obj.ok.deserialize(br.read(size));

    var size = br.readVarintNum();
    obj.sk = new blsct.mcl.G1();
    obj.sk.deserialize(br.read(size));

    obj.bp = {}

    size = br.readVarintNum();
    obj.bp.V =[]
    if (size !== 0) {
      for (var i = 0; i < size; i++) {
        var size_ = br.readVarintNum();
        obj.bp.V[i] = new blsct.mcl.G1();
        obj.bp.V[i].deserialize(br.read(size_));
      }
    }

    size = br.readVarintNum();
    obj.bp.L = []
    if (size !== 0) {
      for (var i = 0; i < size; i++) {
        var size_ = br.readVarintNum();
        obj.bp.L[i] = new blsct.mcl.G1();
        obj.bp.L[i].deserialize(br.read(size_));
      }
    }

    size = br.readVarintNum();
    obj.bp.R =[]
    if (size !== 0) {
      for (var i = 0; i < size; i++) {
        var size_ = br.readVarintNum();
        obj.bp.R[i] = new blsct.mcl.G1();
        obj.bp.R[i].deserialize(br.read(size_));
      }
    }

    size = br.readVarintNum();
    obj.bp.A = new blsct.mcl.G1();
    obj.bp.A.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.S = new blsct.mcl.G1();
    obj.bp.A.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.T1 = new blsct.mcl.G1();
    obj.bp.A.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.T2 = new blsct.mcl.G1();
    obj.bp.A.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.taux = new blsct.mcl.Fr();
    obj.bp.taux.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.mu = new blsct.mcl.Fr();
    obj.bp.mu.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.a = new blsct.mcl.Fr();
    obj.bp.a.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.b = new blsct.mcl.Fr();
    obj.bp.b.deserialize(br.read(size));

    size = br.readVarintNum();
    obj.bp.t = new blsct.mcl.Fr();
    obj.bp.t.deserialize(br.read(size));
  }
  var size = br.readVarintNum();
  if (size !== 0) {
    obj.script = br.read(size);
  } else {
    obj.script = new buffer.Buffer([]);
  }
  return new Output(obj);
};

Output.prototype.toBufferWriter = function(writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  if ((this.ek && this.ek.length > 0) || (this.ok && this.ok.length > 0) || (this.sk && this.sk.length > 0)) {
      writer.writeUInt64LEBN(BN.fromNumber(0xFFFFFFFFFFFFFFFF));
      writer.writeUInt64LEBN(this._satoshisBN);
      writer.writeVarintNum(this.ek.serialize().length);
      writer.write(this.ek.serialize());
      writer.writeVarintNum(this.ok.serialize().length);
      writer.write(this.ok.serialize());
      writer.writeVarintNum(this.sk.serialize().length);
      writer.write(this.sk.serialize());
      writer.writeVarintNum(obj.bp.V.length);
      if (obj.bp.V.length > 0) {
        for (var i = 0; i < obj.bp.V.length; i++) {
          writer.writeVarintNum(this.obj.bp.V[i].serialize().length);
          writer.write(this.obj.bp.V[i].serialize());
        }
      }
      writer.writeVarintNum(obj.bp.L.length);
      if (obj.bp.L.length > 0) {
        for (var i = 0; i < obj.bp.L.length; i++) {
          writer.writeVarintNum(this.obj.bp.L[i].serialize().length);
          writer.write(this.obj.bp.L[i].serialize());
        }
      }
      writer.writeVarintNum(obj.bp.R.length);
      if (obj.bp.R.length > 0) {
        for (var i = 0; i < obj.bp.R.length; i++) {
          writer.writeVarintNum(this.obj.bp.R[i].serialize().length);
          writer.write(this.obj.bp.R[i].serialize());
        }
      }
      writer.writeVarintNum(this.obj.bp.A.serialize().length);
      writer.write(this.obj.bp.A.serialize());
      writer.writeVarintNum(this.obj.bp.S.serialize().length);
      writer.write(this.obj.bp.S.serialize());
      writer.writeVarintNum(this.obj.bp.T1.serialize().length);
      writer.write(this.obj.bp.T1.serialize());
      writer.writeVarintNum(this.obj.bp.T2.serialize().length);
      writer.write(this.obj.bp.T2.serialize());
      writer.writeVarintNum(this.obj.bp.taux.serialize().length);
      writer.write(this.obj.bp.taux.serialize());
      writer.writeVarintNum(this.obj.bp.mu.serialize().length);
      writer.write(this.obj.bp.mu.serialize());
      writer.writeVarintNum(this.obj.bp.a.serialize().length);
      writer.write(this.obj.bp.a.serialize());
      writer.writeVarintNum(this.obj.bp.b.serialize().length);
      writer.write(this.obj.bp.b.serialize());
      writer.writeVarintNum(this.obj.bp.t.serialize().length);
      writer.write(this.obj.bp.t.serialize());
  } else {
      writer.writeUInt64LEBN(this._satoshisBN);
  }
  var script = this._scriptBuffer;
  writer.writeVarintNum(script.length);
  writer.write(script);
  return writer;
};

module.exports = Output;
