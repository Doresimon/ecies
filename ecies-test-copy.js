//dependency
const crypto = require('crypto');
const EC = require('elliptic').ec;

// Create and initialize EC context
// (better do it once and reuse it)
let ec = new EC('curve25519');


//suppose Alice and Bob

//step 0
// two guys generate their own private key and public key
// send public key to each other
let Alice = ec.genKeyPair();
// let x = Alice.getPrivate();
let privateA = Alice.getPrivate();
// let H = Alice.getPublic();
let publicA = Alice.getPublic();

let Bob = ec.genKeyPair();
// let r = Bob.getPrivate();
let privateB = Bob.getPrivate();
// let gTilde = Bob.getPublic();
let publicB = Bob.getPublic();

// when Alice want to send message to Bob

// Alice use Bob's public key to calculate hTilde = [privateA]*publicA
// Alice use her public key as gTlide
let gTilde = publicA;
let hTilde = publicB.mul(privateA);

let out = gTilde.encode('hex');
let PEH = hTilde.getX().toString('hex');

// Alice calculate derivedKey for aes enc
let derivedKey = crypto.pbkdf2Sync(out, PEH, 10086, 32, 'sha256');

// Alice use aes encryption to encrypt message.
let iv = "1234567890123456"; //32Byte   ???
let text = 'TextMustBe16Bytexxxxx';
let algorithm = "aes-256-cbc";
let cipher = crypto.createCipheriv(algorithm, derivedKey, iv);
let msg_cxt = cipher.update(text, 'utf8', 'hex');
msg_cxt += cipher.final('hex');

// Alice send 1,2,3 to Bob
// 1. iv = "1234567890123456";
// 2. msg_cxt
// 3. out(encoded gTlide)

console.log("text");
console.log(text);

console.log("Alice sends:");
console.log("iv");
console.log(iv);
console.log("out");
console.log(out);
console.log("msg_cxt");
console.log(msg_cxt);



/* ******************************************** */
// when Bob receives the 1,2,3 sent from Alice
// bob decodes out to get gTlide
let _gTilde = ec.keyFromPublic(out,"hex").getPublic();
console.log("gTilde");
console.log(gTilde);
console.log("_gTilde");
console.log(_gTilde);

// Bob calculate _hTlide with his privateB and _gTlide
// Bob calculate _PEH from _hTlide
let _hTilde = _gTilde.mul(privateB);
let _PEH = _hTilde.getX().toString('hex');

// Bob calculate derivedKey for aes dec
let _derivedKey = crypto.pbkdf2Sync(out, _PEH, 10086, 32, 'sha256');
 
// Bob use aes decryption to decrypt cipher text.
let _iv = iv;
let _algorithm = "aes-256-cbc";
let decipher = crypto.createDecipheriv(_algorithm, _derivedKey, _iv);
let plain = decipher.update(msg_cxt, 'hex', 'utf8');
plain += decipher.final('utf8');

console.log("text");
console.log(text);
console.log("plain");
console.log(plain);


// function kdfSha256(s, l) {
//     let DigestSize = 32;
//     let hash = require('hash.js');
//
//     let b = Math.ceil(l/DigestSize);
//     let counter = 1;
//     let key = [];
//     let offset = l - (b-1)*DigestSize;
//     while(counter < b){
//         key[counter-1] = hash.sha1().update(s+counter).digest('hex').substring(0,offset);
//         counter++
//     }
//     key[b-1] = hash.sha1().update(s+(b-1)).digest('hex').substring(0,offset)
//
//     return key
// }