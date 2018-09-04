'use strict';

const Buffer = require('buffer');
const crypto = require('crypto');
const EC = require('elliptic').ec;
const pkcs7 = require('pkcs7');

export class Ecies {
    alg = "aes-256-cbc";
    hash = "sha256";
    code = "ascii";
    DigestSize = 32;
    keyFormat = "hex";
    iv = crypto.randomBytes(16);
    ec = new EC('curve25519');
    keyPair = this.ec.genKeyPair();

    constructor(Curve = "curve25519", iv?: Buffer, privHex?: string) {
        this.ec = new EC(Curve);
        this.iv = iv;

        if (privHex) {
            this.setKeyPair(privHex)
        }
    }

    generateKeyPair() {
        this.keyPair = this.ec.genKeyPair();
        return {
            priv: this.keyPair.getPrivate("hex"),
            pub: this.keyPair.getPublic("hex"),
        }
    };

    setKeyPair(privHex: string) {
        this.keyPair = this.ec.keyFromPrivate(privHex, "hex");
    };

    getKeyPair() {
        return {
            priv: this.keyPair.getPrivate("hex"),
            pub: this.keyPair.getPublic("hex"),
        }
    };

    setCurve(curve: string) {
        this.ec = new EC(curve);
    };

    getCurve() {
        return this.ec.curve;
    };

    setHash(hashFunc: string) {
        this.hash = hashFunc;
    };

    getHash() {
        return this.hash;
    };

    enc(H: string, msg: string, iv: any) {
        let publicB = this.ec.keyFromPublic(H, "hex").getPublic();

        let gTilde = this.keyPair.getPublic();
        let hTilde = publicB.mul(this.keyPair.getPrivate());

        let out = gTilde.encode('hex');
        let PEH = hTilde.getX().toString('hex');

        let derivedKeyArray = this.kdf2(out + PEH, 256, this.DigestSize, this.hash);
        if (!derivedKeyArray) {
            return
        }
        let derivedKey = Buffer.Buffer.from(derivedKeyArray[0], "utf8");

        iv = iv || this.iv;

        let algorithm = this.alg;
        let cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
        cipher.setAutoPadding(false);

        let msg_cxt = cipher.update(Buffer.Buffer.from(pkcs7.pad(Buffer.Buffer.from(msg, "utf8"))), "utf8", 'hex') + cipher.final("hex");

        return {
            iv: iv.toString("hex"),
            out: out,
            msg_cxt: msg_cxt,
        };
    };


    dec(msg_cxt: string, out: string, iv: any) {
        let _gTilde = this.ec.keyFromPublic(out, "hex").getPublic();

        let _hTilde = _gTilde.mul(this.keyPair.getPrivate());
        let _PEH = _hTilde.getX().toString('hex');

        let _derivedKeyArray = this.kdf2(out + _PEH, 256, this.DigestSize, this.hash);
        if (!_derivedKeyArray) {
            return
        }
        let _derivedKey = Buffer.Buffer.from(_derivedKeyArray[0], "utf8");

        let _iv = Buffer.Buffer.from(iv, "hex") || function () {
            console.error("iv is missed!");
        };
        let _algorithm = this.alg;
        let decipher = crypto.createDecipheriv(_algorithm, _derivedKey, _iv);
        decipher.setAutoPadding(false);
        let plain = decipher.update(msg_cxt, 'hex', "utf8") + decipher.final("utf8");

        return Buffer.Buffer.from(pkcs7.unpad(Buffer.Buffer.from(plain, "utf8"))).toString("utf8")
    };


    /* utils */
    kdf2(seed: string | Buffer | DataView, len: number, DigestSize: number, hashFunc: string): Buffer[] {
        if (len < 0) return [];
        let l_byte = Math.ceil(len / 8);

        let b = Math.ceil(l_byte / DigestSize);
        let counter = 1; //1 for pbkdf2, 0 for pbkdf1
        let key = [];
        let offset = l_byte - (b - 1) * DigestSize; //byte offset

        while (counter < b) {
            let hash = crypto.createHash(hashFunc);
            key[counter - 1] = hash.update(seed + this.I2OSP(counter, 4)).digest().toString("ascii", 0, DigestSize);  //must be ascii
            counter++
        }
        let hash = crypto.createHash(hashFunc);
        key[counter - 1] = hash.update(seed + this.I2OSP(counter, 4)).digest().toString("ascii", 0, offset);
        return key
    }

    I2OSP(m: number, l: number): string {
        let buf = Buffer.Buffer.allocUnsafe(l);
        buf.writeUIntBE(m, 0, l);
        return buf.toString("ascii")
    }
}