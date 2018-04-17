'use strict';

//dependency
const crypto = require('crypto');
const EC = require('elliptic').ec;

// Create and initialize EC context
// (better do it once and reuse it)
let ec = new EC('curve25519');

let ecies = {
    alg: "aes-256-cbc",
    hash: "sha256",
    keyPair: null,
};
// when Alice want to send message to Bob
ecies.enc = function (H, msg, iv) {
    let publicB = ec.keyFromPublic(H,"hex").getPublic();

    // Alice use Bob's public key to calculate hTilde = [privateA]*publicA
    // Alice use her public key as gTlide
    let gTilde = this.keyPair.getPublic();
    let hTilde = publicB.mul(this.keyPair.getPrivate());

    let out = gTilde.encode('hex');
    let PEH = hTilde.getX().toString('hex');

    // Alice calculate derivedKey for aes enc
    let derivedKey = crypto.pbkdf2Sync(out, PEH, 10086, 32, this.hash);

    // Alice use aes encryption to encrypt message.
    iv  =   iv  || crypto.randomBytes(16);

    let algorithm = this.alg;
    let cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
    let msg_cxt = cipher.update(msg, 'utf8', 'hex');
    msg_cxt += cipher.final('hex');

    return {
        iv:iv,
        out:out,
        msg_cxt:msg_cxt,
    };
};

ecies.dec = function (msg_cxt, out, iv) {
    // when Bob receives the 1,2,3 sent from Alice
    // bob decodes out to get gTlide
    let _gTilde = ec.keyFromPublic(out,"hex").getPublic();

    // Bob calculate _hTlide with his privateB and _gTlide
    // Bob calculate _PEH from _hTlide
    let _hTilde = _gTilde.mul(this.keyPair.getPrivate());
    let _PEH = _hTilde.getX().toString('hex');

    // Bob calculate derivedKey for aes dec
    let _derivedKey = crypto.pbkdf2Sync(out, _PEH, 10086, 32, this.hash);

    // Bob use aes decryption to decrypt cipher text.
    let _iv  =   iv  || function () { console.error("iv is missed!");  };
    let _algorithm = this.alg;
    let decipher = crypto.createDecipheriv(_algorithm, _derivedKey, _iv);
    let plain = decipher.update(msg_cxt, 'hex', 'utf8');
    plain += decipher.final('utf8');

    return plain
};

ecies.generateKeyPair = function () {
    this.keyPair = ec.genKeyPair();
    return  {
        priv: this.keyPair.getPrivate("hex"),
        pub: this.keyPair.getPublic("hex"),
    }
};

ecies.setKeyPair = function (privHex) {
    this.keyPair = ec.keyFromPrivate(privHex,"hex");
};

ecies.getKeyPair = function () {
    return  {
        priv: this.keyPair.getPrivate("hex"),
        pub: this.keyPair.getPublic("hex"),
    }
};

ecies.setCurve = function (curve) {
    ec = new EC(curve);
};

ecies.getCurve = function () {
    return ec.curve;
};

ecies.setHash = function (h) {
    this.hash = h;
};

ecies.getHash = function () {
    return this.hash;
};

exports.ecies = ecies;