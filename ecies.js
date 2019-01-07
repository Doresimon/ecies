'use strict';

const Buffer = require('buffer').Buffer;
const crypto = require('crypto');
const EC = require('elliptic').ec;
const pkcs7 = require('pkcs7');

let ecies = {
    alg: "aes-256-cbc",
    hash: "sha256",
    code: "ascii",
    DigestSize: 32,
    keyFormat: "hex",
    iv: "",
    ec: null,
    keyPair: null,
};
ecies.ec = new EC('curve25519');
ecies.iv = crypto.randomBytes(16);

ecies.enc = function (H, msg, iv) {
    let publicB = ecies.ec.keyFromPublic(H,"hex").getPublic();

    let gTilde = this.keyPair.getPublic();
    let hTilde = publicB.mul(this.keyPair.getPrivate());

    let out = gTilde.encode('hex');
    let PEH = hTilde.getX().toString('hex');

    let derivedKeyArray = kdf2(out+PEH, 256, ecies.DigestSize, ecies.hash);
    let derivedKey = Buffer.from(derivedKeyArray[0],"utf8");

    iv  =   iv  || ecies.iv;

    let algorithm = this.alg;
    let cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
    cipher.setAutoPadding(false);

    let msg_cxt = cipher.update(Buffer.from(pkcs7.pad(Buffer.from(msg,"utf8"))), "utf8", 'hex') + cipher.final("hex");

    return {
        iv:iv.toString("hex"),
        out:out,
        msg_cxt:msg_cxt,
    };
};

ecies.dec = function (msg_cxt, out, iv) {
    let _gTilde = ecies.ec.keyFromPublic(out,"hex").getPublic();

    let _hTilde = _gTilde.mul(this.keyPair.getPrivate());
    let _PEH = _hTilde.getX().toString('hex');

    let _derivedKeyArray = kdf2(out+_PEH, 256, ecies.DigestSize, ecies.hash);
    let _derivedKey = Buffer.from(_derivedKeyArray[0],"utf8");

    let _iv  =   Buffer.from(iv,"hex")  || function () { console.error("iv is missed!");  };
    let _algorithm = this.alg;
    let decipher = crypto.createDecipheriv(_algorithm, _derivedKey, _iv);
    decipher.setAutoPadding(false);
    let plain = decipher.update(msg_cxt, 'hex', "utf8") + decipher.final("utf8");

    return Buffer.from( pkcs7.unpad( Buffer.from( plain,"utf8" ) ) ).toString("utf8")
};

ecies.generateKeyPair = function () {
    this.keyPair = ecies.ec.genKeyPair();
    return  {
        priv: this.keyPair.getPrivate("hex"),
        pub: this.keyPair.getPublic("hex"),
    }
};

ecies.setKeyPair = function (privHex) {
    this.keyPair = ecies.ec.keyFromPrivate(privHex,"hex");
};

ecies.getKeyPair = function () {
    return  {
        priv: this.keyPair.getPrivate("hex"),
        pub: this.keyPair.getPublic("hex"),
    }
};

ecies.setCurve = function (curve) {
    ecies.ec = new EC(curve);
};

ecies.getCurve = function () {
    return ecies.ec.curve;
};

ecies.setHash = function (hashFunc) {
    this.hash = hashFunc;
};

ecies.getHash = function () {
    return this.hash;
};

/* utils */
function kdf2(seed, bit_length, digest_byte_size, hash_func_name) {
    if (bit_length<0) return null;
    let l_byte = Math.ceil(bit_length/8);

    let b = Math.ceil(l_byte/digest_byte_size);
    let counter = 1; //1 for pbkdf2, 0 for pbkdf1
    let key = [];
    let offset = l_byte - (b-1)*digest_byte_size; //byte offset

    while(counter < b){
        let hash = crypto.createHash(hash_func_name);
        key[counter-1] = hash.update(seed+I2OSP(counter, 4)).digest().toString("ascii", 0, digest_byte_size);  //must be ascii
        counter++
    }
    let hash = crypto.createHash(hash_func_name);
    key[counter-1] = hash.update(seed+I2OSP(counter, 4)).digest().toString("ascii", 0, offset);
    return key
}

ecies.kdf = kdf2;

function I2OSP(m, l) {
    let buf = Buffer.allocUnsafe(l);
    buf.writeUIntBE(m, 0, l);
    return buf.toString("ascii");
}

exports.ecies = ecies;