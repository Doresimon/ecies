'use strict';
/* global describe it */

let assert = require('assert');

const ecies = require('./../ecies').ecies;

describe('ecies', function() {
    function test(fn, cases) {
        for (let i = 0; i < cases.length; i++) {
            let keyB = ecies.generateKeyPair();
            let keyA = ecies.generateKeyPair();
            let msg = cases[i];
            // let iv = ""
            let cxt = ecies.enc(keyB.pub, msg);


            ecies.setKeyPair(keyB.priv);
            let plain = ecies.dec(cxt.msg_cxt, cxt.out,  cxt.iv);

            assert.equal(plain, msg);
        }
    }

    it('check self correctness', function() {
        // assert.equal(hash.sha256.blockSize, 512);
        // assert.equal(hash.sha256.outSize, 256);
        test(ecies, [
            "",
            "hello world",
            "qwertyuiopasdfghjklzxcvbnm1234567890",
        ]);
    });
});






//
//
//
//
//
//
// let priv = '0a6aed3f0099eab4aec8ca45d06684e7228e98c83044321eb81d8b4919bc2f8f';
// let privB =  '0fc9775c67772cbb89dbd3d7a7b0db1ce51f46cdd361b0d4308b953df0da9380';
// let pubB =  '6b42d8eb0c1f0581652a3e6fd6c6dee5b5a7114a5640684e59658f25bcb130ca';
// let msg =  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';
// let iv = "1234567890123456"; //32Byte   ???
//
// ecies.setKeyPair(priv);
// let cxt = ecies.enc(pubB, msg, iv);
//
// ecies.setKeyPair(privB);
// let plain = ecies.dec(cxt.msg_cxt, cxt.out,  cxt.iv);
//
//
// console.log(msg)
// console.log(cxt)
// console.log(plain)