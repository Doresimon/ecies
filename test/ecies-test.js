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