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


            ecies.setKeyPair(keyA.priv);
            let cxt = ecies.enc(keyB.pub, msg);



            ecies.setKeyPair(keyB.priv);
            let plain = ecies.dec(cxt.msg_cxt, cxt.out,  cxt.iv);

            console.log("************************************");
            console.log("msg: ",msg);
            console.log("cxt: ",cxt);
            console.log("plain: ",plain);

            assert.equal(plain, msg);
        }
    }

    it('check self correctness', function() {
        test(ecies, [
            "",
            "12345",
            "hello world",
            "qwertyuiopasdfghjklzxcvbnm1234567890",
            "一去二三里",
        ]);
    });
});