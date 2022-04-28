const SHA256 = require("bcrypto/lib/sha256");
const HKDF = require("bcrypto/lib/hkdf");
const BN_ = require("bn.js");

const ikmToLamportSK = (ikm, salt) => {
    const bIKM = Buffer.from(ikm);
    const prk = HKDF.extract(SHA256, bIKM, salt);
    const okm = HKDF.expand(SHA256, prk, Buffer.alloc(0), 8160); // 8160 = 255 * 32
    return Array.from({length: 255}, (_, i) => okm.slice(i*32, (i+1)*32));
}

const parentSKToLamportPK = (parentSK, index)  => {
    const bytesArray = (n) => {
        let buf = new Buffer((n.toString(16).length % 2 ? '0' : '') + n.toString(16), 'hex')

        let a = [];

        for (var i = 0; i < buf.length; i++) {
            a.push(buf.readUInt8(i));
        }

        while (a.length != 4) {
            a.unshift(0)
        }

        return new Uint8Array(a)
    }
    const salt = new Buffer(bytesArray(index));
    const ikm = Buffer.from(parentSK);
    const lamport0 = ikmToLamportSK(ikm, salt);
    const notIkm = Buffer.from(ikm.map((value) => ~value));
    const lamport1 = ikmToLamportSK(notIkm, salt);
    const lamportPK = lamport0.concat(lamport1).map((value) => SHA256.digest(value));
    return SHA256.digest(Buffer.concat(lamportPK));
}

const hkdfModR = (ikm, keyInfo = Buffer.alloc(0))  => {
    let salt = Buffer.from("BLS-SIG-KEYGEN-SALT-", "ascii");
    let sk = new BN_(0);
    while (!sk.cmp(new BN_(0))) {
        //salt = SHA256.digest(salt);
        const prk = HKDF.extract(
            SHA256,
            Buffer.concat([ikm, Buffer.alloc(1)]),
            salt
        );

        const okm = HKDF.expand(SHA256, prk, Buffer.concat([keyInfo, Buffer.from([0, 48])]), 48);
        const okmBN = new BN_(okm, "hex", "be");

        const r = new BN_("52435875175126190479447740508185965837690552500527637822603658699938581184513");
        sk = okmBN.mod(r);
    }
    return Buffer.from(sk.toArray("be", 32));
}

module.exports.deriveChildSK = (parentSK, index)  => {
    if (!Buffer.isBuffer(parentSK) || parentSK.length > 32) {
        throw new Error("parentSK must be a Buffer of 32 bytes");
    }
    if (parentSK.length !== 32) {
        while(parentSK.length !== 32) {
            parentSK = Buffer.concat([Buffer.alloc(32-parentSK.length), parentSK]);
        }
    }
    if (!Number.isSafeInteger(index) || index < 0 || index >= 2 ** 32) {
        throw new Error("index must be 0 <= i < 2**32");
    }
    const compressedLamportPK = parentSKToLamportPK(parentSK, index);
    return hkdfModR(compressedLamportPK);
}

module.exports.deriveMasterSK = (ikm) => {
    if (!Buffer.isBuffer(ikm)) {
        throw new Error("ikm must be a Buffer");
    }
    if (ikm.length < 32) {
        throw new Error("ikm must be >= 32 bytes");
    }
    return hkdfModR(ikm);
}

module.exports.deriveChildSKMultiple = (parentSK, indices)  => {
    let key = parentSK;
    indices.forEach(i => key = deriveChildSK(key, i));
    return key;
}
