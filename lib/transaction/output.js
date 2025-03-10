"use strict";

var _ = require("lodash");
var BN = require("../crypto/bn");
var buffer = require("buffer");
var bufferUtil = require("../util/buffer");
var JSUtil = require("../util/js");
var BufferWriter = require("../encoding/bufferwriter");
var BufferReader = require("../encoding/bufferreader");
var Script = require("../script");
var $ = require("../util/preconditions");
var errors = require("../errors");
var blsct = require("../crypto/blsct");

var MAX_SAFE_INTEGER = 0x1fffffffffffff;

function Output(args) {
  if (!(this instanceof Output)) {
    return new Output(args);
  }
  if (_.isObject(args)) {
    this.satoshis = args.satoshis;
    this.ok = new blsct.mcl.G1();
    let isZero = (el) => {
      if (typeof el == 'string')
        el = Buffer.from(el, 'hex');
      if (!el || el.length == 0) return true;
      for (var i in el) {
        if (el[i] != 0x0) return false;
      }
      return true;
    };
    if (args.ok && !isZero(args.ok)) {
      this.ok.deserializeHexStr(args.ok);
    }
    this.ek = new blsct.mcl.G1();
    if (args.ek && !isZero(args.ek)) {
      this.ek.deserializeHexStr(args.ek);
    }
    this.sk = new blsct.mcl.G1();
    if (args.sk && !isZero(args.sk)) {
      this.sk.deserializeHexStr(args.sk);
    }

    this.vData = args.vData || new buffer.Buffer([]);
    this.tokenId = args.tokenId || new buffer.Buffer(new Uint8Array(32));
    this.tokenNftId = args.tokenNftId || -1;

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

    if (args.bp) {
      for (var i in args.bp.V) {
        this.bp.V.push(new blsct.mcl.G1());
        this.bp.V[i].deserializeHexStr(args.bp.V[i]);
      }

      for (var i in args.bp.L) {
        this.bp.L.push(new blsct.mcl.G1());
        this.bp.L[i].deserializeHexStr(args.bp.L[i]);
      }

      for (var i in args.bp.R) {
        this.bp.R.push(new blsct.mcl.G1());
        this.bp.R[i].deserializeHexStr(args.bp.R[i]);
      }

      this.bp.A.deserializeHexStr(args.bp.A);
      this.bp.S.deserializeHexStr(args.bp.S);
      this.bp.T1.deserializeHexStr(args.bp.T1);
      this.bp.T2.deserializeHexStr(args.bp.T2);

      this.bp.taux.deserializeHexStr(args.bp.taux);
      this.bp.mu.deserializeHexStr(args.bp.mu);
      this.bp.a.deserializeHexStr(args.bp.a);
      this.bp.b.deserializeHexStr(args.bp.b);
      this.bp.t.deserializeHexStr(args.bp.t);
    }

    if (bufferUtil.isBuffer(args.script)) {
      this._scriptBuffer = args.script;
    } else {
      var script;
      if (_.isString(args.script) && JSUtil.isHexa(args.script)) {
        script = new buffer.Buffer(args.script, "hex");
      } else {
        script = args.script;
      }
      this.setScript(script);
    }
  } else {
    throw new TypeError("Unrecognized argument for Output");
  }
}

Object.defineProperty(Output.prototype, "script", {
  configurable: false,
  enumerable: true,
  get: function () {
    if (this._script) {
      return this._script;
    } else {
      this.setScriptFromBuffer(this._scriptBuffer);
      return this._script;
    }
  },
});

Object.defineProperty(Output.prototype, "satoshis", {
  configurable: false,
  enumerable: true,
  get: function () {
    return this._satoshis;
  },
  set: function (num) {
    if (num instanceof BN) {
      this._satoshisBN = num;
      this._satoshis = num.toNumber();
    } else if (_.isString(num)) {
      this._satoshis = parseInt(num);
      this._satoshisBN = BN.fromNumber(this._satoshis);
    } else {
      $.checkArgument(
          JSUtil.isNaturalNumber(num),
          "Output satoshis is not a natural number"
      );
      this._satoshisBN = BN.fromNumber(num);
      this._satoshis = num;
    }
    $.checkState(
        JSUtil.isNaturalNumber(this._satoshis),
        "Output satoshis is not a natural number"
    );
  },
});

Output.prototype.invalidSatoshis = function () {
  if (this._satoshis > MAX_SAFE_INTEGER) {
    return "transaction txout satoshis greater than max safe integer";
  }
  if (this._satoshis !== this._satoshisBN.toNumber()) {
    return "transaction txout satoshis has corrupted value";
  }
  if (this._satoshis < 0) {
    return "transaction txout negative";
  }
  return false;
};

Output.prototype.isCt = function () {
  return (this.bp && this.bp.V && this.bp.V.length);
};

Output.prototype.isNft = function () {
  return this.tokenNftId.toString() != -1 && this.hasBlsctKeys();
}

Output.prototype.hasBlsctKeys = function () {
  return (
      (this.ek && !this.ek.isZero()) ||
      (this.ok && !this.ok.isZero()) ||
      (this.sk && !this.sk.isZero())
  );
};

Output.prototype.toObject = Output.prototype.toJSON = function toObject() {
  var obj = {
    satoshis: this.satoshis,
  };
  obj.script = this._scriptBuffer.toString("hex");
  if (this.bp && this.bp.V && this.bp.V.length) {
    obj.bp = {
      V: [],
      L: [],
      R: [],
      A: (new blsct.mcl.G1()).serializeToHexStr(),
      S: (new blsct.mcl.G1()).serializeToHexStr(),
      T1: (new blsct.mcl.G1()).serializeToHexStr(),
      T2: (new blsct.mcl.G1()).serializeToHexStr(),
      taux: (new blsct.mcl.G1()).serializeToHexStr(),
      a: (new blsct.mcl.G1()).serializeToHexStr(),
      b: (new blsct.mcl.G1()).serializeToHexStr(),
      t: (new blsct.mcl.G1()).serializeToHexStr(),
      mu: (new blsct.mcl.G1()).serializeToHexStr(),
    };
    if (this.bp) {
      if (this.bp.V) {
        for (var i in this.bp.V) {
          obj.bp.V.push(this.bp.V[i].serializeToHexStr());
        }
        for (var i in this.bp.L) {
          obj.bp.L.push(this.bp.L[i].serializeToHexStr());
        }
        for (var i in this.bp.R) {
          obj.bp.R.push(this.bp.R[i].serializeToHexStr());
        }
      }
      if (this.bp.A) obj.bp.A = this.bp.A.serializeToHexStr();
      if (this.bp.S) obj.bp.S = this.bp.S.serializeToHexStr();
      if (this.bp.T1) obj.bp.T1 = this.bp.T1.serializeToHexStr();
      if (this.bp.T2) obj.bp.T2 = this.bp.T2.serializeToHexStr();
      if (this.bp.taux) obj.bp.taux = this.bp.taux.serializeToHexStr();
      if (this.bp.mu) obj.bp.mu = this.bp.mu.serializeToHexStr();
      if (this.bp.a) obj.bp.a = this.bp.a.serializeToHexStr();
      if (this.bp.b) obj.bp.b = this.bp.b.serializeToHexStr();
      if (this.bp.t) obj.bp.t = this.bp.t.serializeToHexStr();
    }
    obj.ek = this.ek ? this.ek.serializeToHexStr() : (new mcl.G1()).serializeToHexStr();
    obj.ok = this.ok ? this.ok.serializeToHexStr() : (new mcl.G1()).serializeToHexStr();
    obj.sk = this.sk ? this.sk.serializeToHexStr() : (new mcl.G1()).serializeToHexStr();
  }
  obj.vData = this.vData;
  obj.tokenId = this.tokenId;
  obj.tokenNftId = this.tokenNftId;
  return obj;
};

Output.fromObject = function (data) {
  return new Output(data);
};

Output.prototype.setScriptFromBuffer = function (buffer) {
  this._scriptBuffer = buffer;
  try {
    this._script = Script.fromBuffer(this._scriptBuffer);
    this._script._isOutput = true;
  } catch (e) {
    if (e instanceof errors.Script.InvalidBuffer) {
      this._script = null;
    } else {
      throw e;
    }
  }
};

Output.prototype.setScript = function (script) {
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
    throw new TypeError("Invalid argument type: script");
  }
  return this;
};

Output.prototype.inspect = function () {
  var scriptStr;
  if (this.script) {
    scriptStr = this.script.inspect();
  } else {
    scriptStr = this._scriptBuffer.toString("hex");
  }
  return "<Output (" + this.satoshis + " sats) " + scriptStr + ">";
};

Output.fromBufferReader = function (br) {
  var obj = {};
  var flags = br.readUInt64LEBN();
  if (flags == 0xffffffffffffffff) {
    obj.satoshis = br.readUInt64LEBN();

    obj.ek = blsct.DeserializeG1(br);
    obj.ok = blsct.DeserializeG1(br);
    obj.sk = blsct.DeserializeG1(br);
    obj.bp = blsct.DeserializeProof(br);
  } else if (flags.toBuffer()[0] == 0x80 && flags.toBuffer().len == 8) {
    if (flags.toBuffer()[7] & (0x1 << 0)) {
      obj.satoshis = br.readUInt64LEBN();
    } else {
      obj.satoshis = 0;
    }
    if (flags.toBuffer()[7] & (0x1 << 1)) {
      obj.ek = blsct.DeserializeG1(br);
    }
    if (flags.toBuffer()[7] & (0x1 << 2)) {
      obj.ok = blsct.DeserializeG1(br);
    }
    if (flags.toBuffer()[7] & (0x1 << 3)) {
      obj.sk = blsct.DeserializeG1(br);
    }

    if (flags.toBuffer()[7] & (0x1 << 4)) {
      obj.bp = blsct.DeserializeProof(br);
    }
    if (flags.toBuffer()[7] & (0x1 << 5)) {
      obj.tokenId = br.read(32).reverse();
    }
    if (flags.toBuffer()[7] & (0x1 << 6)) {
      obj.tokenNftId = br.readUInt64LEBN();
    }
    if (flags.toBuffer()[7] & (0x1 << 7)) {
      var size = br.readVarintNum();
      if (size !== 0) {
        obj.vData = br.read(size);
      } else {
        obj.vData = new buffer.Buffer([]);
      }
    }
  } else {
    obj.satoshis = flags;
  }
  var size = br.readVarintNum();
  if (size !== 0) {
    obj.script = br.read(size);
  } else {
    obj.script = new buffer.Buffer([]);
  }
  return new Output(obj);
};

Output.prototype.fromBuffer = function (buffer) {
  var reader = new BufferReader(buffer);
  return this.fromBufferReader(reader);
};

Output.prototype.toBufferWriter = function (writer) {
  if (!writer) {
    writer = new BufferWriter();
  }
  let isZero = true;
  for (let i = 0; i < this.tokenId.length; i++) {
    if (this.tokenId[i] != 0) {
      isZero = false;
      break;
    }
  }
  if (!isZero || this.vData.length > 0 || this.tokenNftId != -1) {
    let flags = 0;
    if (this.satoshis > 0) {
      flags |= 0x1 << 0;
    }
    if (!this.ek.isZero()) flags |= 0x1 << 1;
    if (!this.ok.isZero()) flags |= 0x1 << 2;
    if (!this.sk.isZero()) flags |= 0x1 << 3;
    if (this.bp.V.length > 0) {
      flags |= 0x1 << 4;
    }

    if (!isZero) {
      flags |= 0x1 << 5;
    }
    if (this.tokenNftId != -1) {
      flags |= 0x1 << 6;
    }
    if (this.vData.length > 0) {
      flags |= 0x1 << 7;
    }

    writer.writeReverse(
        new Uint8Array([0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, flags])
    );
    if (flags & (0x1 << 0)) {
      writer.writeUInt64LEBN(this._satoshisBN);
    }
    if (flags & (0x1 << 1)) {
      blsct.SerializeG1(writer, this.ek);
    }
    if (flags & (0x1 << 2)) {
      blsct.SerializeG1(writer, this.ok);
    }
    if (flags & (0x1 << 3)) {
      blsct.SerializeG1(writer, this.sk);
    }
    if (flags & (0x1 << 4)) {
      blsct.SerializeProof(writer, this.bp);
    }
    if (flags & (0x1 << 5)) {
      writer.writeReverse(Buffer.from(this.tokenId));
    }
    if (flags & (0x1 << 6)) {
      writer.writeUInt64LEBN(BN.fromString(this.tokenNftId.toString()));
    }
    if (flags & (0x1 << 7)) {
      writer.writeVarintNum(Buffer.from(this.vData).length);
      writer.write(Buffer.from(this.vData));
    }
  } else if (!this.ek.isZero() || !this.ok.isZero() || !this.sk.isZero()) {
    writer.write(
        new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
    );
    writer.writeUInt64LEBN(this._satoshisBN);
    blsct.SerializeG1(writer, this.ek, true);
    blsct.SerializeG1(writer, this.ok, true);
    blsct.SerializeG1(writer, this.sk, true);
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
