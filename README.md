
## Summary

The main purpose of this project was to integrate a series of cryptographic modules into a simplified and portable library to be used in embedded devices with limited resources.
Some modules are modified versions from third party projects, others were developed from scratch.

## Notes

 - This project is on its alpha stage of development.

## Listing of the supported modules

```
         arch/mem support:	OK
        arch/spec support:	OK

      auth/shadow support:	OK

        crypt/aes support:	OK
   crypt/blowfish support:	OK
     crypt/chacha support:	OK
        crypt/otp support:	OK
      crypt/salsa support:	OK

    decode/base16 support:	OK
    decode/base64 support:	OK

    encode/base16 support:	OK
    encode/base64 support:	OK

  generate/random support:	OK

       hash/blake support:	OK
      hash/blake2 support:	OK
        hash/gost support:	OK
      hash/haval* support:	OK
         hash/md2 support:	OK
         hash/md4 support:	OK
         hash/md5 support:	OK
     hash/ripemd* support:	OK
        hash/sha* support:	OK
      hash/tiger* support:	OK
   hash/whirlpool support:	OK

       kdf/bcrypt support:	OK
         kdf/hkdf support:	OK
       kdf/pbkdf1 support:	OK
       kdf/pbkdf2 support:	OK
       kdf/scrypt support:	OK

        ke/chreke support:	OK
            ke/dh support:	OK
         ke/dheke support:	OK
          ke/ecdh support:	OK

         mac/hmac support:	OK
     mac/poly1305 support:	OK

           tc/mem support:	OK
```
