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
var blsct = require('../crypto/blsct');

var MAX_SAFE_INTEGER = 0x1fffffffffffff;

function Output(args) {
  if (!(this instanceof Output)) {
    return new Output(args);
  }
  if (_.isObject(args)) {
    this.satoshis = args.satoshis;
    this.ok = args.ok && _.isString(args.ok) ? blsct.mcl.deserializeHexStrToG1(args.ok) : args.ok;
    this.ek = args.ek && _.isString(args.ek) ? blsct.mcl.deserializeHexStrToG1(args.ek) : args.ek;
    this.sk = args.sk && _.isString(args.sk) ? blsct.mcl.deserializeHexStrToG1(args.sk) : args.sk;
    this.bp = {V: [], L: [], R: []}
    if (args.bp)
    {
      for (var i in args.bp.V)
      {
        this.bp.V.push(_.isString(args.bp.V[i]) ? blsct.mcl.deserializeHexStrToG1(args.bp.V[i]) : args.bp.V[i])
      }
      for (var i in args.bp.L)
      {
        this.bp.L.push(_.isString(args.bp.L[i]) ? blsct.mcl.deserializeHexStrToG1(args.bp.L[i]) : args.bp.L[i])
      }
      for (var i in args.bp.R)
      {
        this.bp.R.push(_.isString(args.bp.R[i]) ? blsct.mcl.deserializeHexStrToG1(args.bp.R[i]) : args.bp.R[i])
      }
      this.bp.A = args.bp.A && _.isString(args.bp.A) ? blsct.mcl.deserializeHexStrToG1(args.bp.A) : args.bp.A;
      this.bp.S = args.bp.S && _.isString(args.bp.S) ? blsct.mcl.deserializeHexStrToG1(args.bp.S) : args.bp.S;
      this.bp.T1 = args.bp.T1 && _.isString(args.bp.T1) ? blsct.mcl.deserializeHexStrToG1(args.bp.T1) : args.bp.T1;
      this.bp.T2 = args.bp.T2 && _.isString(args.bp.T2) ? blsct.mcl.deserializeHexStrToG1(args.bp.T2) : args.bp.T2;
      this.bp.taux = args.bp.taux && _.isString(args.bp.taux) ? blsct.mcl.deserializeHexStrToFr(args.bp.taux) : args.bp.taux;
      this.bp.mu = args.bp.mu && _.isString(args.bp.mu) ? blsct.mcl.deserializeHexStrToFr(args.bp.mu) : args.bp.mu;
      this.bp.a = args.bp.a && _.isString(args.bp.a) ? blsct.mcl.deserializeHexStrToFr(args.bp.a) : args.bp.a;
      this.bp.b = args.bp.b && _.isString(args.bp.b) ? blsct.mcl.deserializeHexStrToFr(args.bp.b) : args.bp.b;
      this.bp.t = args.bp.t && _.isString(args.bp.t) ? blsct.mcl.deserializeHexStrToFr(args.bp.t) : args.bp.t;
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

Output.prototype.toObject = Output.prototype.toJSON = function toObject() {
  var obj = {
    satoshis: this.satoshis
  };
  obj.script = this._scriptBuffer.toString('hex');
  obj.bp = {V:[],L:[],R:[]};

  if (this.bp)
  {
    for (var i in this.bp.V)
    {
      obj.bp.V.push(this.bp.V[i].serializeToHexStr())
    }
    for (var i in this.bp.L)
    {
      obj.bp.L.push(this.bp.L[i].serializeToHexStr())
    }
    for (var i in this.bp.R)
    {
      obj.bp.R.push(this.bp.R[i].serializeToHexStr())
    }
    obj.bp.A = this.bp.A ? this.bp.A.serializeToHexStr() : '';
    obj.bp.S = this.bp.S ? this.bp.S.serializeToHexStr() : '';
    obj.bp.T1 = this.bp.T1 ? this.bp.T1.serializeToHexStr() : '';
    obj.bp.T2 = this.bp.T2 ? this.bp.T2.serializeToHexStr() : '';
    obj.bp.taux = this.bp.taux ? this.bp.taux.serializeToHexStr() : '';
    obj.bp.mu = this.bp.mu ? this.bp.mu.serializeToHexStr() : '';
    obj.bp.a = this.bp.a ? this.bp.a.serializeToHexStr() : '';
    obj.bp.b = this.bp.b ? this.bp.b.serializeToHexStr() : '';
    obj.bp.t = this.bp.t ? this.bp.t.serializeToHexStr() : '';
  }

  obj.ek = this.ek ? this.ek.serializeToHexStr() : '';
  obj.ok = this.ok ? this.ok.serializeToHexStr() : '';
  obj.sk = this.sk ? this.sk.serializeToHexStr() : '';
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
    if (size > 0) {
      obj.ek = new blsct.mcl.G1();
      obj.ek.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.ok = new blsct.mcl.G1();
      obj.ok.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.sk = new blsct.mcl.G1();
      obj.sk.deserialize(br.read(size));
    }

    obj.bp = {}

    size = br.readVarintNum();
    obj.bp.V =[]
    if (size !== 0) {
      for (var i = 0; i < size; i++) {
        var size_ = br.readVarintNum();
        if (size_ > 0) {
          obj.bp.V[i] = new blsct.mcl.G1();
          obj.bp.V[i].deserialize(br.read(size_));
        }
      }
    }

    size = br.readVarintNum();
    obj.bp.L = []
    if (size !== 0) {
      for (var i = 0; i < size; i++) {
        var size_ = br.readVarintNum();
        if (size_ > 0) {
          obj.bp.L[i] = new blsct.mcl.G1();
          obj.bp.L[i].deserialize(br.read(size_));
        }
      }
    }

    size = br.readVarintNum();
    obj.bp.R =[]
    if (size !== 0) {
      for (var i = 0; i < size; i++) {
        var size_ = br.readVarintNum();
        if (size_ > 0) {
          obj.bp.R[i] = new blsct.mcl.G1();
          obj.bp.R[i].deserialize(br.read(size_));
        }
      }
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.A = new blsct.mcl.G1();
      obj.bp.A.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.S = new blsct.mcl.G1();
      obj.bp.S.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.T1 = new blsct.mcl.G1();
      obj.bp.T1.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.T2 = new blsct.mcl.G1();
      obj.bp.T2.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.taux = new blsct.mcl.Fr();
      obj.bp.taux.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.mu = new blsct.mcl.Fr();
      obj.bp.mu.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.a = new blsct.mcl.Fr();
      obj.bp.a.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.b = new blsct.mcl.Fr();
      obj.bp.b.deserialize(br.read(size));
    }

    size = br.readVarintNum();
    if (size > 0) {
      obj.bp.t = new blsct.mcl.Fr();
      obj.bp.t.deserialize(br.read(size));
    }
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
  if ((this.ek && this.ek.serialize().length > 0) || (this.ok && this.ok.serialize().length > 0) || (this.sk && this.sk.serialize().length > 0)) {
      writer.write(new Uint8Array([0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]));
      writer.writeUInt64LEBN(this._satoshisBN);
      writer.writeVarintNum(this.ek ? this.ek.serialize().length : 48);
      writer.write(this.ek ? this.ek.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.ok ? this.ok.serialize().length : 48);
      writer.write(this.ok ? this.ok.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.sk ? this.sk.serialize().length : 48);
      writer.write(this.sk ? this.sk.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.bp.V.length);
      if (this.bp.V.length > 0) {
        for (var i = 0; i < this.bp.V.length; i++) {
          writer.writeVarintNum(this.bp.V[i].serialize().length);
          writer.write(this.bp.V[i].serialize());
        }
      }
      writer.writeVarintNum(this.bp.L.length);
      if (this.bp.L.length > 0) {
        for (var i = 0; i < this.bp.L.length; i++) {
          writer.writeVarintNum(this.bp.L[i].serialize().length);
          writer.write(this.bp.L[i].serialize());
        }
      }
      writer.writeVarintNum(this.bp.R.length);
      if (this.bp.R.length > 0) {
        for (var i = 0; i < this.bp.R.length; i++) {
          writer.writeVarintNum(this.bp.R[i].serialize().length);
          writer.write(this.bp.R[i].serialize());
        }
      }
      writer.writeVarintNum(this.bp.A ? this.bp.A.serialize().length : 48);
      writer.write(this.bp.A ? this.bp.A.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.bp.S ? this.bp.S.serialize().length : 48);
      writer.write(this.bp.S ? this.bp.S.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.bp.T1 ? this.bp.T1.serialize().length : 48);
      writer.write(this.bp.T1 ? this.bp.T1.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.bp.T2 ? this.bp.T2.serialize().length : 48);
      writer.write(this.bp.T2 ? this.bp.T2.serialize() : new Uint8Array(48));
      writer.writeVarintNum(this.bp.taux ? this.bp.taux.serialize().length : 32);
      writer.write(this.bp.taux ? this.bp.taux.serialize() : new Uint8Array(32));
      writer.writeVarintNum(this.bp.mu ? this.bp.mu.serialize().length : 32);
      writer.write(this.bp.mu ? this.bp.mu.serialize() : new Uint8Array(32));
      writer.writeVarintNum(this.bp.a ? this.bp.a.serialize().length : 32);
      writer.write(this.bp.a ? this.bp.a.serialize() : new Uint8Array(32));
      writer.writeVarintNum(this.bp.b ? this.bp.b.serialize().length : 32);
      writer.write(this.bp.b ? this.bp.b.serialize() : new Uint8Array(32));
      writer.writeVarintNum(this.bp.t ? this.bp.t.serialize().length : 32);
      writer.write(this.bp.t ? this.bp.t.serialize() : new Uint8Array(32));
  } else {
      writer.writeUInt64LEBN(this._satoshisBN);
  }
  var script = this._scriptBuffer;
  writer.writeVarintNum(script.length);
  writer.write(script);
  return writer;
};

module.exports = Output;
