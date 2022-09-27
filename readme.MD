## Encryption demo

Very small demo project part of a presentation. It tries to show a thing or two about hashing and encryption. It is not a proper, secure implementation of anything and should be appraised with that in mind :)

The repo contains two python files that can be run by calling them in the terminal, eg:

```
python ./src/encryptifier.py
```

Note that the encryption demo requires the installation of an additional crypto package, see the requirements file. The hash script can be run without dependencies.

Both scripts run a small terminal application that allows for some interaction with hashing and encryption.

#### Hashing

The hashing script allows the caller to create a user table consisting of username and password combinations. When adding a user the caller is asked to supply a username and password. The username is stored as is, but the password is hashed before being stored. The caller can also try to validate a user. They are asked once again to supply a username and password, but this time the user should already exist. The supplied password is hashed again and compared with the stored hash of the original password.

This shows that for user login validation it is not necessary to store plaintext passwords.

#### Encryption

The encryption demo implements the ChaCha20 encryption of the [pycryptodome package](https://www.pycryptodome.org/src/cipher/chacha20). It creates 3 random keys and 3 random nonces on startup. These can be used to encrypt text supplied by the caller. To use a key or nonce supply a number 1, 2 or 3. For example, to encrypt "message" with the first random key and the third random nonce, type the following in the encrypt function:

message
1
3

The plaintext is not stored, but can be restored by decrypting. To get a correct decrypt result, use the same key and nonce used for encryption. To decrypt you have to supply the desired "number" of the cipher texts. The first encrypted text is 1, the next encrypted text is 2, etc. So if the above example was the first text encrypted in the session, type the following in the decrypt function:

1
1
3

