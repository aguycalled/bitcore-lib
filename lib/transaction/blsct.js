'use strict';

const _ = require('lodash');
const assert = require('assert');
const sha256sha256 = require('../crypto/hash').sha256sha256;
const BN = require('../crypto/bn');
const address = require('../address');
const transaction = require('../transaction');
const script = require('../script');

let { Init, mcl, bls, maxM, maxMN, maxMessageSize, logN, N, balanceMsg,
      Transcript, HashG1Element, CombineUint8Array, G, H, Gi, Hi, one,
      two, twoN, ip12, oneN, zero, bytesArray, VectorCommitment,
      VectorSubtract, VectorPowers, VectorAdd, VectorScalar, VectorSlice,
      CrossVectorExponent, Hadamard, VectorAddSingle, InnerProduct,
      HadamardFold, VectorPowerSum, subAddressPrefix, ripemd160, sha256,
      orderMinusOne} = require('../crypto/blsct');

const BIP32_HARDENED_KEY_LIMIT = 0x0; //0x80000000;

class Blsct {
    constructor ()
    {
        this.mcl = mcl;
        this.bls = bls;
        this.Init = Init;
    }

    RangeVerify (proofs, vData, nonces, fOnlyRecover, fTest= false) {
        let fRecover = false;

        if (nonces.length == proofs.length)
        {
            fRecover = true;
        }

        let max_length = 0;
        let nV = 0;

        let proof_data = [];

        let inv_offset = 0, j = 0;
        let to_invert = [];

        for (var pi in proofs)
        {
            let proof = proofs[pi].proof;
            let nonce = nonces[pi];
            let index = proofs[pi].index;

            if (!(proof.V.length >= 1 && proof.L.length === proof.R.length &&
                proof.L.length > 0))
            {
                return false;
            }

            max_length = Math.max(max_length, proof.L.length);
            nV += proof.V.length;

            proof_data[proof_data.length];
            let pd = proof_data[proof_data.length];
            pd = {};
            pd.V = proof.V;

            let transcript = new Transcript()

            transcript.add(pd.V[0].serialize());

            for (var vi = 1; vi < pd.V.length; vi++)
            {
                transcript.add(pd.V[vi].serialize());
            }

            transcript.add(proof.A.serialize());
            transcript.add(proof.S.serialize());

            pd.y = new mcl.Fr();
            pd.y.setBigEndianMod(transcript.getHash());

            transcript.add(pd.y.serialize());

            pd.z = new mcl.Fr();
            pd.z.setBigEndianMod(transcript.getHash());

            transcript.add(pd.z.serialize());
            transcript.add(proof.T1.serialize());
            transcript.add(proof.T2.serialize());

            pd.x = new mcl.Fr();
            pd.x.setBigEndianMod(transcript.getHash());

            transcript.add(pd.x.serialize());
            transcript.add(proof.taux.serialize());
            transcript.add(proof.mu.serialize());
            transcript.add(proof.t.serialize());

            pd.x_ip = new mcl.Fr();
            pd.x_ip.setBigEndianMod(transcript.getHash());

            let M;
            let _logM;
            for (_logM = 0; (M = 1<<_logM) <= maxM && M < pd.V.length; _logM++);

            pd.logM = new mcl.Fr();
            pd.logM.setInt(_logM);

            let logNFr = new mcl.Fr();
            logNFr.setInt(logN);

            let rounds = parseInt(mcl.add(pd.logM, logNFr).getStr());

            pd.w = [];
            for (var i = 0; i < rounds; ++i)
            {
                transcript.add(proof.L[i].serialize());
                transcript.add(proof.R[i].serialize());

                pd.w[i] = new mcl.Fr()
                pd.w[i].setBigEndianMod(transcript.getHash());
            }

            pd.inv_offset = inv_offset;
            for (var i = 0; i < rounds; ++i)
            {
                to_invert.push(pd.w[i]);
            }

            to_invert.push(pd.y);
            inv_offset += rounds + 1;

            if (fRecover)
            {
                let gamma = new mcl.Fr();
                gamma.setBigEndianMod(HashG1Element(nonce, 100))

                let alpha = new mcl.Fr();
                alpha.setBigEndianMod(HashG1Element(nonce, 1))

                let rho = new mcl.Fr();
                rho.setBigEndianMod(HashG1Element(nonce, 2))

                let tau1 = new mcl.Fr();
                tau1.setBigEndianMod(HashG1Element(nonce, 3))

                let tau2 = new mcl.Fr();
                tau2.setBigEndianMod(HashG1Element(nonce, 4))

                let excess = mcl.sub(mcl.sub(proof.mu, mcl.mul(rho, pd.x)), alpha);
                let excessSer = excess.serialize();
                let amount = new mcl.Fr();
                amount.setBigEndianMod(excessSer.slice(excessSer.length-8, excessSer.length))

                let data = {};
                data.index = index;

                let buffer = Buffer.from(amount.serialize().slice(excessSer.length-8, excessSer.length));
                data.amount = BN.fromBuffer(buffer).toNumber()

                let excessMsg = new TextDecoder().decode(excessSer.slice(0, excessSer.length-8).filter(e => e != 0 && e != 1))
                let fFoundNonzero = false;

                data.gamma = gamma;

                let excessSer2 = mcl.sub(mcl.mul(mcl.sub(mcl.sub(proof.taux, mcl.mul(tau2, mcl.mul(pd.x, pd.x))), mcl.mul(pd.z, mcl.mul(pd.z, gamma))), mcl.inv(pd.x)), tau1)

                let excessMsg2 = new TextDecoder().decode(excessSer2.serialize().filter(e => e != 0 && e != 1))

                fFoundNonzero = false;

                data.message = excessMsg + excessMsg2;

                {
                    let fIsMine = mcl.add(mcl.mul(G(),gamma), mcl.mul(H(),amount)).isEqual(pd.V[0]);

                    data.isMine = fIsMine;
                    vData.push(data);
                }

                j++;
            }

            proof_data[proof_data.length] = pd;
        }

        if (fOnlyRecover)
            return true;

        let maxMN = 1 << max_length;

        let inverses = Array(to_invert);

        for (var ti in to_invert)
        {
            inverses[ti] = mcl.inv(to_invert[ti]);
        }

        let z1 = new mcl.Fr();
        let z3 = new mcl.Fr();

        let z4 = [];
        let z5 = [];

        for (var i = 0; i < maxMN; i++)
        {
            z4[i] = new mcl.Fr();
            z5[i] = new mcl.Fr();
        }

        let y0 = new mcl.Fr();
        let y1 = new mcl.Fr();

        let tmp  = new mcl.Fr();

        let proof_data_index = 0;

        let bases = [];
        let exps = [];

        for (var pp in proofs)
        {
            let proof = proofs[pp].proof;

            let pd = proof_data[proof_data_index++];

            if (proof.L.length != logN+parseInt(pd.logM.getStr()))
                return false;

            let M = 1 << parseInt(pd.logM.getStr());

            let MN = M*N;

            let weight_y = new mcl.Fr();
            weight_y.setByCSPRNG();
            let weight_z = new mcl.Fr();
            weight_z.setByCSPRNG();

            y0 = mcl.sub(y0, mcl.mul(proof.taux, weight_y));

            let zpow = VectorPowers(pd.z, M+3);

            let ip1y = VectorPowerSum(pd.y, MN);

            let k = mcl.neg(mcl.mul(zpow[2], ip1y));

            for (var ki = 1; ki <= M; ++ki)
            {
                k = mcl.sub(k, mcl.mul(zpow[ki+2],ip12()));
            }

            tmp = mcl.add(k, mcl.mul(pd.z, ip1y));

            tmp = mcl.sub(proof.t, tmp);

            y1 = mcl.add(y1, mcl.mul(tmp, weight_y));

            for (var ki = 0; ki < pd.V.length; ki++)
            {
                tmp = mcl.mul(zpow[ki+2], weight_y);
                bases.push(mcl.deserializeHexStrToG1(pd.V[ki].serializeToHexStr()))
                exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()));
            }

            tmp = mcl.mul(pd.x, weight_y);

            bases.push(mcl.deserializeHexStrToG1(proof.T1.serializeToHexStr()))
            exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()));

            tmp = mcl.mul(pd.x, mcl.mul(pd.x, weight_y));

            bases.push(mcl.deserializeHexStrToG1(proof.T2.serializeToHexStr()))
            exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()));

            bases.push(mcl.deserializeHexStrToG1(proof.A.serializeToHexStr()))
            exps.push(mcl.deserializeHexStrToFr(weight_z.serializeToHexStr()));

            tmp = mcl.mul(pd.x, weight_z);

            bases.push(mcl.deserializeHexStrToG1(proof.S.serializeToHexStr()))
            exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()));

            let logNFr = new mcl.Fr();
            logNFr.setInt(logN);

            let rounds = parseInt(mcl.add(pd.logM, logNFr).getStr(10));

            let yinvpow = mcl.deserializeHexStrToFr(one().serializeToHexStr());
            let ypow = mcl.deserializeHexStrToFr(one().serializeToHexStr());
            let winv = inverses.slice(pd.inv_offset);
            let yinv = mcl.deserializeHexStrToFr(inverses[pd.inv_offset + rounds].serializeToHexStr());

            let w_cache = Array(1<<rounds);

            w_cache[0] = mcl.deserializeHexStrToFr(winv[0].serializeToHexStr());
            w_cache[1] = mcl.deserializeHexStrToFr(pd.w[0].serializeToHexStr());

            for (var i = 2; i < 1<<rounds; i++) {
                w_cache[i] = mcl.deserializeHexStrToFr(one().serializeToHexStr());
            }

            for (var ki = 1; ki < rounds; ++ki)
            {
                let sl = 1<<(ki+1);
                for (var s = sl; s-- > 0; --s)
                {
                    w_cache[s] = mcl.mul(w_cache[parseInt(s/2)], pd.w[ki]);
                    w_cache[s-1] = mcl.mul(w_cache[parseInt(s/2)], winv[ki]);
                }
            }

            for (var i = 0; i < MN; ++i)
            {
                let g_scalar = mcl.deserializeHexStrToFr(proof.a.serializeToHexStr());

                let h_scalar;

                if (i == 0)
                    h_scalar = mcl.deserializeHexStrToFr(proof.b.serializeToHexStr());
                else {
                    h_scalar = mcl.mul(proof.b, yinvpow);
                }

                g_scalar = mcl.mul(g_scalar, w_cache[i] || new mcl.Fr());
                h_scalar = mcl.mul(h_scalar, w_cache[(~i) & (MN-1)] || new mcl.Fr());

                g_scalar = mcl.add(g_scalar, pd.z);
                tmp = mcl.mul(zpow[parseInt(2+i/N)], twoN()[i%N]);

                if (i == 0)
                {
                    tmp = mcl.add(tmp, pd.z);
                    h_scalar = mcl.sub(h_scalar, tmp);
                }
                else
                {
                    tmp = mcl.add(tmp, mcl.mul(pd.z, ypow));
                    h_scalar = mcl.sub(h_scalar, mcl.mul(tmp, yinvpow));
                }

                z4[i] = mcl.sub(z4[i], mcl.mul(g_scalar, weight_z));
                z5[i] = mcl.sub(z5[i], mcl.mul(h_scalar, weight_z));

                if (i == 0)
                {
                    yinvpow = mcl.deserializeHexStrToFr(yinv.serializeToHexStr());
                    ypow = mcl.deserializeHexStrToFr(pd.y.serializeToHexStr());
                }
                else if (i != MN-1)
                {
                    yinvpow = mcl.mul(yinvpow, yinv);
                    ypow = mcl.mul(ypow, pd.y);
                }
            }

            z1 = mcl.add(z1, mcl.mul(proof.mu, weight_z));

            for (var i = 0; i < rounds; ++i)
            {
                tmp = mcl.mul(pd.w[i], mcl.mul(pd.w[i], weight_z));

                bases.push(proof.L[i])
                exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()))

                tmp = mcl.mul(winv[i], mcl.mul(winv[i], weight_z));

                bases.push(proof.R[i])
                exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()))
            }

            tmp = mcl.sub(proof.t, mcl.mul(proof.a,proof.b));
            tmp = mcl.mul(tmp, pd.x_ip);
            z3 = mcl.add(z3, mcl.mul(tmp, weight_z));
        }

        tmp = mcl.sub(y0, z1);

        bases.push(G())
        exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()))

        tmp = mcl.sub(z3, y1);

        bases.push(H())
        exps.push(mcl.deserializeHexStrToFr(tmp.serializeToHexStr()))

        for (var i = 0; i < maxMN; ++i)
        {
            bases.push(Gi()[i])
            exps.push(z4[i])

            bases.push(Hi()[i])
            exps.push(z5[i])
        }

        let mexp = mcl.mulVec(bases, exps);

        return mexp.isZero();
    }

    AugmentedSign(pk, msg) {
        let pk_ = bls().PrivateKey.from_bytes(pk.serialize(), true)
        return bls().AugSchemeMPL.sign(pk_, msg);
    }

    BasicSign(pk, msg) {
        let pk_ = bls().PrivateKey.from_bytes(pk.serialize(), true)
        return bls().BasicSchemeMPL.sign(pk_, msg);
    }

    AugmentedVerify (pk, sig, msg) {
        let pk_ = bls().PublicKey.from_bytes(pk.serialize(), true)
        return bls().AugSchemeMPL.verify(pk_, sig, msg);
    }

    G () {
        return G();
    }

    H () {
        return H();
    }

    GenKey () {
        const pk = new mcl.Fr();
        pk.setByCSPRNG();
        return pk;
    }

    SkToPubKey (key) {
        if (_.isString(key)) {
            return this.SkToPubKey(mcl.deserializeHexStrToFr(key))
        }

        return mcl.mul(G(), key);
    }

    CreateBLSCTOutput (dest, amount, memo) {
        if (_.isString(dest))
            return this.CreateBLSCTOutput(new address(dest), amount, memo);

        if (!(dest instanceof address && dest.isXnav()))
            throw new TypeError("dest should be a xNAV address")

        let output = new transaction.Output({satoshis: 0, script: script.fromHex("51")})

        let values = [];

        output.amount = amount;
        values.push(amount);

        let bk = new mcl.Fr();
        bk.setByCSPRNG();

        let destViewKey = new mcl.G1();
        destViewKey.deserialize(dest.hashBuffer.slice(1,49));

        let destSpendKey = new mcl.G1();
        destSpendKey.deserialize(dest.hashBuffer.slice(49));

        let nonce = mcl.mul(destViewKey, bk);

        let gamma = new mcl.Fr();
        gamma.setBigEndianMod(HashG1Element(nonce, 100));
        output.gamma = gamma;

        output.memo = memo;

        let hashNonce = new mcl.Fr()
        hashNonce.setBigEndianMod(HashG1Element(nonce, 0));

        output.bp = this.RangeProve(values, nonce, memo)
        output.ek = mcl.mul(G(), bk);
        output.ok = mcl.mul(destSpendKey, bk);
        output.sk = mcl.add(destSpendKey, mcl.mul(G(), hashNonce))

        let valueFr = new mcl.Fr();
        valueFr.setBigEndianMod(bytesArray(amount))
        assert(mcl.add(mcl.mul(G(), output.gamma), mcl.mul(H(), valueFr)).isEqual(output.bp.V[0]))

        let hash = sha256sha256(output.toBufferWriter().toBuffer());
        output.blstxsig = this.AugmentedSign(bk, hash);
        output.outhash = hash;

        return output;
    }

    CreateTransaction(from, dest, amount, memo, vk, sk) {
        if (_.isString(dest))
            return this.CreateTransaction(from, new address(dest), amount, memo, vk, sk);

        if (_.isString(vk) || _.isString(sk)) {
            return this.CreateTransaction(from, dest, amount, memo, mcl.deserializeHexStrToFr(vk), mcl.deserializeHexStrToFr(sk))
        }

        let tx = transaction();
        var sigs = [];
        var keys = [];
        var msgs = [];
        let toXnav = dest.isXnav();
        let gammasIn = new mcl.Fr();
        let gammasOut = new mcl.Fr();

        let balk = new mcl.G1();

        let addedInputs = 0;

        for (var out_i in from)
        {
            let out = from[out_i];

            if (!out.output.isCt())
                throw new TypeError("you can only spend xnav outputs")

            if (!this.IsMine(out.output, vk, sk))
            {
                console.log('not mine')
                continue;
            }

            this.RecoverBLSCTOutput(out.output, vk, sk)

            let utxo = transaction.UnspentOutput({
                "txid" : out.txid,
                "vout" : parseInt(out.vout),
                "scriptPubKey" : script.empty(),
                "satoshis" : out.output.amount
            })

            addedInputs += out.output.amount;

            tx.from(utxo,undefined, undefined, undefined, out.output);

            gammasIn = mcl.add(gammasIn, out.output.gamma)

            balk = mcl.add(balk, out.output.bp.V[0])

            let hash = sha256sha256(tx.inputs[tx.inputs.length-1].toBufferWriter().toBuffer());

            let sig = this.AugmentedSign(out.output.sigk, hash)
            let key = bls().G1Element.from_bytes(out.output.sk.serialize());

            console.log(out.output.sigk)

            assert(bls().G1Element.from_bytes(out.output.sk.serialize()).equal_to(
                bls().PrivateKey.from_bytes(out.output.sigk.serialize(), true).get_g1()
                ))

            sigs.push(sig)
            keys.push(key)
            msgs.push(hash)

            assert(bls().AugSchemeMPL.verify(key, hash, sig))

            if (addedInputs >= amount+200000*(tx.inputs.length+3))
                break;
        }

        let {viewKey, spendKey} = this.DerivePublicKeys(vk, sk);
        let destOutput;

        if (toXnav)
        {
            destOutput = this.CreateBLSCTOutput(dest, amount, memo);
            gammasOut = mcl.add(gammasOut, destOutput.gamma);

            balk = mcl.sub(balk, destOutput.bp.V[0])
        }
        else
        {
            destOutput = new transaction.Output({satoshis: amount, script: script.fromAddress(dest)})
            let bk = new mcl.Fr();
            bk.setByCSPRNG();
            destOutput.ek = mcl.mul(G(), bk);
        }

        tx.addOutput(destOutput);
        tx.addOutput(new transaction.Output({satoshis: 200000*(tx.inputs.length+3), script: script.fromHex("6a")}))

        let changeOutput = this.CreateBLSCTOutput(this.KeysToAddress(viewKey, spendKey).toString(), tx.inputAmount-tx.outputAmount, "Change");

        balk = mcl.sub(balk, changeOutput.bp.V[0])

        sigs.push(destOutput.blstxsig);
        keys.push(bls().G1Element.from_bytes(destOutput.ek.serialize()))
        msgs.push(destOutput.outhash)
        sigs.push(changeOutput.blstxsig);
        keys.push(bls().G1Element.from_bytes(changeOutput.ek.serialize()))
        msgs.push(changeOutput.outhash)

        gammasOut = mcl.add(gammasOut, changeOutput.gamma);

        tx.addOutput(changeOutput);

        tx.vchtxsig = bls().AugSchemeMPL.aggregate(sigs).serialize();

        assert(bls().AugSchemeMPL.aggregate_verify(keys, msgs, bls().G2Element.from_bytes(tx.vchtxsig)))

        let balSigKey = mcl.sub(gammasIn, gammasOut);
        this.SigBalance(tx, balSigKey);

        return tx;
    }

    SigBalance(tx, key)
    {
        tx.vchbalsig = this.BasicSign(key, balanceMsg).serialize();
    }

    RecoverBLSCTOutput (out, vk, sk) {
        if (!out.isCt())
            return;

        if (_.isString(vk) || _.isString(sk)){
            return this.RecoverBLSCTOutput(out, mcl.deserializeHexStrToFr(vk), mcl.deserializeHexStrToFr(sk))
        }

        let vData = [];

        let nonce = mcl.mul(out.ok, vk);

        if (!this.RangeVerify([{proof:out.bp,index:0}], vData, [nonce], true))
            return;

        if (!vData[0].isMine)
            return;

        out.gamma = vData[0].gamma;
        out.amount = vData[0].amount;
        out.memo = vData[0].message;
        if (sk)
            out.sigk = this.RecoverSpendKey(out, vk, sk);

        return out;
    }

    GetHashId (out, vk) {
        if (_.isString(vk)){
            return this.RecoverHashId(out, mcl.deserializeHexStrToFr(vk))
        }

        let t = mcl.mul(out.ok, vk);
        let hash_t = new mcl.Fr();
        hash_t.setBigEndianMod(HashG1Element(t, 0));

        let dh = mcl.add(out.sk, mcl.mul(mcl.mul(G(), hash_t), mcl.neg(one())));

        return ripemd160(sha256(dh.serialize()));
    }

    RecoverSpendKey (out, vk, sk, acct=0, index=0) {
        if (_.isString(vk) || _.isString(sk)){
            return this.RecoverSpendKey(out, mcl.deserializeHexStrToFr(vk), mcl.deserializeHexStrToFr(sk), acct, index)
        }

        const transcript = new Transcript()

        transcript.add(subAddressPrefix);
        transcript.add(vk.serialize());
        transcript.add(bytesArray(acct));
        transcript.add(bytesArray(index));

        let transcriptFr = new mcl.Fr();
        transcriptFr.setBigEndianMod(transcript.getHash())

        let t = mcl.mul(out.ok, vk)
        let hash_t = new mcl.Fr()
        hash_t.setBigEndianMod(HashG1Element(t, 0))
        let k = mcl.add(hash_t, mcl.add(sk, transcriptFr));

        return k;
    }

    IsMine (out, vk, sk, acct=0, index=0) {
        if (_.isString(vk) || _.isString(sk)){
            return this.RecoverSpendKey(out, mcl.deserializeHexStrToFr(vk), mcl.deserializeHexStrToFr(sk), acct, index)
        }

        return out.sk.isEqual(mcl.mul(G(), this.RecoverSpendKey(out, vk, sk, acct, index)));
    }

    DeriveMasterKeys(mk) {
        let mkHash = new Transcript().add(mk.toBuffer()).getHash();

        let masterBLSKey = bls().BasicSchemeMPL.key_gen(mkHash);
        let childBLSKey = bls().BasicSchemeMPL.derive_child_sk(masterBLSKey, BIP32_HARDENED_KEY_LIMIT|130);
        let transactionBLSKey = bls().BasicSchemeMPL.derive_child_sk(childBLSKey, BIP32_HARDENED_KEY_LIMIT);
        let blindingBLSKey = bls().BasicSchemeMPL.derive_child_sk(childBLSKey, BIP32_HARDENED_KEY_LIMIT|1);
        let viewKey = bls().BasicSchemeMPL.derive_child_sk(transactionBLSKey, BIP32_HARDENED_KEY_LIMIT);
        let spendKey = bls().BasicSchemeMPL.derive_child_sk(transactionBLSKey, BIP32_HARDENED_KEY_LIMIT|1);

        let vk = new mcl.Fr();
        let sk = new mcl.Fr();
        let bk = new mcl.Fr();

        vk.deserialize(viewKey.serialize());
        sk.deserialize(spendKey.serialize());
        bk.deserialize(blindingBLSKey.serialize());

        return {masterViewKey: vk, masterSpendKey: sk, masterBlindingKey: bk};
    }

    DerivePublicKeys(vk, sk, acc=0, index=0) {
        if (_.isString(vk) || _.isString(sk)){
            return this.DerivePublicKeys(mcl.deserializeHexStrToFr(vk), mcl.deserializeHexStrToFr(sk), acct, index)
        }

        const transcript = new Transcript()

        transcript.add(subAddressPrefix);
        transcript.add(vk.serialize());
        transcript.add(bytesArray(acc));
        transcript.add(bytesArray(index));

        let transcriptFr = new mcl.Fr();
        transcriptFr.setBigEndianMod(transcript.getHash())

        let transcriptFrPk = mcl.mul(G(), transcriptFr);
        let skPk = new mcl.G1();
        skPk.deserialize(mcl.mul(G(), sk).serialize());
        let spendKey = mcl.add(transcriptFrPk, skPk);
        let viewKey = mcl.mul(spendKey, vk);

        return {viewKey: viewKey, spendKey: spendKey};
    }

    KeysToAddress (vk, sk, network="mainnet") {
        if ((sk instanceof mcl.Fr) || (vk instanceof mcl.Fr))
        {
            return this.KeysToAddress(mcl.mul(G, sk), mcl.mul(G, vk))
        }

        if (_.isString(vk) || _.isString(sk)){
            return this.KeysToAddress(mcl.deserializeHexStrToG1(vk), mcl.deserializeHexStrToG1(sk))
        }

        if (!(sk instanceof mcl.G1 && vk instanceof mcl.G1))
            return;

        return address.fromBuffers([new Buffer([0x49, 0x21]), vk.serialize(), sk.serialize()], network, "xnav")
    }

    RangeProve (values, nonce, msg, fTest=false) {
        let hrTime = process.hrtime()
        let start = (hrTime[0] * 1000000 + hrTime[1] / 1000)

        assert(msg.length <= maxMessageSize);

        var M, logM;
        for (logM = 0; (M = 1<<logM) <= maxM && M < values.length; ++logM);
        assert(M <= maxM);
        var logMN = logM + logN;
        var MN = M*N;
        let proof;

        while (true)
        {
            proof = {V: []};

            const transcript = new Transcript()

            let gamma = [], valuesFr = [];

            for (var i = 0; i < values.length; i++)
            {
                gamma[i] = new mcl.Fr();
                gamma[i].setBigEndianMod(HashG1Element(nonce, 100+i))

                var value = values[i];

                let v = new mcl.Fr();
                v.setBigEndianMod(bytesArray(value))

                valuesFr[i] = v;
                proof.V[i] = mcl.add(mcl.mul(G(), gamma[i]), mcl.mul(H(), v));

                transcript.add(proof.V[i].serialize())
            }

            let aL = [], aR = []

            for (var j = 0; j < M; ++j)
            {
                let vBytes = valuesFr.length > j ? valuesFr[j].serialize() : [];

                for (var i = 0; i < N; ++i)
                {
                    let byteIndex = vBytes.length-1-parseInt(i/8)
                    let bitIndex = i%8

                    if ((vBytes[byteIndex]>>bitIndex)&1 == 1)
                    {
                        aL[j*N+i] = one();
                        aR[j*N+i] = zero();
                    }
                    else
                    {
                        aL[j*N+i] = zero();
                        aR[j*N+i] = mcl.neg(one());
                    }
                }
            }

            let message = new mcl.Fr();
            message.setBigEndianMod(Uint8Array.from(Buffer.concat([Buffer.from(new TextEncoder().encode(msg.substr(0,23))), new Buffer(bytesArray(parseInt(valuesFr[0].getStr())))])))

            let alpha = new mcl.Fr();
            alpha.setBigEndianMod(HashG1Element(nonce, 1))

            alpha = mcl.add(alpha, message);

            proof.A = mcl.add(VectorCommitment(aL, aR), mcl.mul(G(), alpha));

            transcript.add(proof.A.serialize());

            let x = new mcl.Fr();
            let x_ip = new mcl.Fr();
            let y = new mcl.Fr();
            let z = new mcl.Fr();
            let sL = [], sR = [];

            try {
                for (var i = 0; i < MN; ++i)
                {
                    let r1 = one();
                    sL[i] = r1;

                    let r2 = one();
                    sR[i] = r2;
                }

                let rho = new mcl.Fr();
                rho.setBigEndianMod(HashG1Element(nonce, 2))

                proof.S = mcl.add(VectorCommitment(sL, sR), mcl.mul(G(), rho));

                transcript.add(proof.S.serialize());

                y.setBigEndianMod(transcript.getHash());

                if (y.isZero())
                    continue;

                transcript.add(y.serialize());

                z.setBigEndianMod(transcript.getHash());

                if (z.isZero())
                    continue;

                let l0 = VectorSubtract(aL, z);
                let l1 = sL.slice();

                let zerostwos = [];
                let zpow = VectorPowers(z, M+2);

                for (var j = 0; j < M; ++j)
                {
                    for (var i = 0; i < N; ++i)
                    {
                        assert(j+2 < zpow.length);
                        assert(i < twoN().length);
                        zerostwos[j*N+i] = mcl.mul(zpow[j+2], twoN()[i]);
                    }
                }

                let yMN = VectorPowers(y, MN);
                let r0 = VectorAdd(Hadamard(VectorAddSingle(aR, z), yMN), zerostwos);

                if (fTest)
                {
                    const lefthandside = mcl.add(mcl.mul(mcl.mul(z, z), valuesFr[0]), Delta(yMN, z))
                    const righthandside = InnerProduct(l0, r0);

                    // Now we got a single vector product proving our 3 statements wHi()ch can be easily verified
                    // as is done() below:
                    assert(lefthandside.isEqual(righthandside));
                }

                let r1 = Hadamard(yMN, sR);

                // Polynomial construction before PAPER LINE 51
                let t1 = mcl.add(InnerProduct(l0, r1), InnerProduct(l1, r0));
                let t2 = InnerProduct(l1, r1);

                // PAPER LINES 52-53
                let tau1 = new mcl.Fr();
                tau1.setBigEndianMod(HashG1Element(nonce, 3))

                let tau2 = new mcl.Fr();
                tau2.setBigEndianMod(HashG1Element(nonce, 4))

                let secondMessage = new mcl.Fr();
                secondMessage.setBigEndianMod(new TextEncoder().encode(msg.substr(23)))

                tau1 = mcl.add(tau1, secondMessage);

                proof.T1 = mcl.add(mcl.mul(H(), t1),mcl.mul(G(), tau1))
                proof.T2 = mcl.add(mcl.mul(H(), t2),mcl.mul(G(), tau2))

                transcript.add(z.serialize());
                transcript.add(proof.T1.serialize());
                transcript.add(proof.T2.serialize());

                x.setBigEndianMod(transcript.getHash());

                if (x.isZero())
                    continue;

                let l = VectorAdd(l0, VectorScalar(l1, x));
                let r = VectorAdd(r0, VectorScalar(r1, x));

                // PAPER LINE 60
                proof.t = InnerProduct(l, r);

                // TEST
                let t0 = InnerProduct(l0, r0);
                let test_t = mcl.add(mcl.add(t0, mcl.mul(t1,x)), mcl.mul(t2,mcl.mul(x,x)));
                if (fTest && !(test_t.isEqual(proof.t)))
                {
                    console.error("BulletproofsRangeproof::Prove(): L60 Invalid test");
                    process.exit(-1)
                }

                // PAPER LINES 61-62
                proof.taux = mcl.add(mcl.mul(tau1, x), mcl.mul(tau2, mcl.mul(x, x)));

                for (var j = 1; j <= M; j++) // note this starts from 1
                {
                    proof.taux = mcl.add(proof.taux, mcl.mul(zpow[j+1], gamma[j-1]||new mcl.Fr()));
                }

                if (fTest)
                {
                    // TEST
                    let d = Delta(yMN, z);
                    let zsq = mcl.mul(z, z);
                    let xsq = mcl.mul(x, x);

                    assert(mcl.add(mcl.mul(H(), mcl.mul(zsq, valuesFr[0])), mcl.mul(G(), mcl.mul(zsq, gamma[0]))).isEqual(
                        mcl.mul(proof.V[0], zsq)
                    ))

                    assert(mcl.add(mcl.add(mcl.mul(H(), mcl.mul(zsq, valuesFr[0])), mcl.mul(G(), mcl.mul(zsq, gamma[0]))), mcl.mul(H(), d)).isEqual(
                        mcl.add(mcl.mul(proof.V[0], zsq), mcl.mul(H(), d))
                    ))

                    assert(mcl.add(mcl.mul(H(), mcl.mul(x, t1)), mcl.mul(G(), mcl.mul(x, tau1))).isEqual(
                        mcl.mul(proof.T1, x)
                    ))

                    assert(mcl.add(mcl.mul(H(), mcl.mul(xsq, t2)), mcl.mul(G(), mcl.mul(xsq, tau2))).isEqual(
                        mcl.mul(proof.T2, xsq)
                    ))

                    let test_tx = mcl.add(mcl.add(mcl.mul(zsq, gamma[0]), mcl.mul(x, tau1)), mcl.mul(xsq, tau2))
                    const left = mcl.add(mcl.mul(H(), test_t), mcl.mul(G(), test_tx))
                    const right = mcl.add(mcl.add(mcl.add(mcl.mul(proof.V[0], zsq), mcl.mul(H(), d)), mcl.mul(proof.T1, x)), mcl.mul(proof.T2, xsq))

                    assert(left.isEqual(right))
                }

                proof.mu = mcl.add(mcl.mul(x, rho), alpha);

                // PAPER LINE 63
                transcript.add(x.serialize());
                transcript.add(proof.taux.serialize());
                transcript.add(proof.mu.serialize());
                transcript.add(proof.t.serialize());

                x_ip.setBigEndianMod(transcript.getHash());

                if (x_ip.isZero())
                    continue;

                let nprime = MN;

                let gprime = [];
                let hprime = [];
                let aprime = [];
                let bprime = [];

                let yinv = mcl.inv(y);

                let yinvpow = [];

                yinvpow[0] = mcl.deserializeHexStrToFr(one().serializeToHexStr());
                yinvpow[1] = mcl.deserializeHexStrToFr(yinv.serializeToHexStr());

                for (var i = 0; i < nprime; i++)
                {
                    gprime[i] = Gi()[i];
                    hprime[i] = Hi()[i];

                    if(i > 1)
                        yinvpow[i] = mcl.mul(yinvpow[i-1], yinv);

                    aprime[i] = mcl.deserializeHexStrToFr(l[i].serializeToHexStr());
                    bprime[i] = mcl.deserializeHexStrToFr(r[i].serializeToHexStr());
                }

                if (fTest)
                {
                    let zsq = mcl.mul(z, z);
                    const vecH = VectorDup(H(), yMN.length);
                    const vecG = VectorDup(G(), yMN.length);
                    const vecH2 = Hadamard(vecH, yinvpow);
                    const e = mcl.mul(G(), proof.mu)
                    const einv = mcl.neg(e)
                    const vecz = VectorDup(z, yMN.length);

                    const l1_ = VectorAdd(VectorScalar(yMN, z), VectorScalar(twoN(), zsq))
                    const l2_ = VectorAdd(vecz, Hadamard(VectorScalar(yinvpow, zsq), twoN()))

                    const P1 = mcl.add(mcl.add(mcl.add(mcl.add(einv, proof.A), mcl.mul(proof.S, x)), InnerProduct(Hadamard(vecH2, l1_), oneN())), mcl.neg(InnerProduct(Hadamard(vecG, vecz), oneN())))
                    const P2 = mcl.add(mcl.add(mcl.add(mcl.add(einv, proof.A), mcl.mul(proof.S, x)), InnerProduct(Hadamard(vecH, l2_), oneN())), mcl.neg(InnerProduct(Hadamard(vecG, vecz), oneN())))

                    assert(P1.isEqual(P2))
                }

                proof.L = [];
                proof.R = [];

                let round = 0;
                let w = [];

                let scale = yinvpow.slice();

                while (nprime > 1)
                {
                    // PAPER LINE 20
                    nprime = parseInt(nprime / 2);

                    // PAPER LINES 21-22
                    let cL = InnerProduct(VectorSlice(aprime, 0, nprime), VectorSlice(bprime, nprime, bprime.length));

                    let cR = InnerProduct(VectorSlice(aprime, nprime, aprime.length), VectorSlice(bprime, 0, nprime));

                    // PAPER LINES 23-24
                    proof.L[round] = CrossVectorExponent(nprime, gprime, nprime, hprime, 0, aprime, 0, bprime, nprime, scale, H(), mcl.mul(cL, x_ip));
                    proof.R[round] = CrossVectorExponent(nprime, gprime, 0, hprime, nprime, aprime, nprime, bprime, 0, scale, H(), mcl.mul(cR, x_ip));

                    // PAPER LINES 25-27
                    transcript.add(proof.L[round].serialize());
                    transcript.add(proof.R[round].serialize());

                    w[round] = new mcl.Fr();
                    w[round].setBigEndianMod(transcript.getHash());

                    if (w[round].isZero())
                        continue;

                    let winv = mcl.inv(w[round]);

                    // PAPER LINES 29-31
                    if (nprime > 1)
                    {
                        gprime = HadamardFold(gprime, undefined, winv, w[round]);
                        hprime = HadamardFold(hprime, scale, w[round], winv);
                    }

                    // PAPER LINES 33-34
                    aprime = VectorAdd(VectorScalar(VectorSlice(aprime, 0, nprime), w[round]),
                        VectorScalar(VectorSlice(aprime, nprime, aprime.length), winv));

                    bprime = VectorAdd(VectorScalar(VectorSlice(bprime, 0, nprime), winv),
                        VectorScalar(VectorSlice(bprime, nprime, bprime.length), w[round]));

                    scale = undefined;

                    round += 1;
                }

                proof.a = aprime[0];
                proof.b = bprime[0];

                break;
            }
            catch(e)
            {
                console.log(e)
                continue;
            }

        }

        if (fTest)
        {
            let hrTime2 = process.hrtime()
            let end = (hrTime2[0] * 1000000 + hrTime2[1] / 1000)

            console.log(`Took ${(end-start)/1000}ms`)
        }

        return proof;
    }
}

module.exports = new Blsct();
