
# install dependency
> npm i elliptic
> npm i pkcs7


# use

## init
> const ecies = require('./ecies').ecies;
* default curve is curve25519
* default encryption scheme is aes-256-cbc, digest size = 32 bytes

## generate key pair
> let keys = ecies.generateKeyPair();
## get private key (hex encoding)
> let privateKey = keys.priv;
## get public key (hex encoding)
> let publicKey = keys.pub;

## encrypt a message
> let cxt = ecies.enc(keyOtherPub, msg, iv);
* keyOtherPub is the other guy's public key(hex)
* msg is type string.
* iv is optional, it will be generated randomly.
* return 

        {
            iv: hex string,
            out: hex string,
            msg_cxt: hex string,
        }
      
## decrypt a message
> let plain = ecies.dec(cxt.msg_cxt, cxt.out, cxt.iv);
* return 

       plain text