# `cryptobox` a.k.a "poor man's HSM".

Prerequisites:
- `macOS`/`Linux`/popular `*nix`
- `git`
- `conan`
- `cmake`
- `make`
- `g++` > 7

Build instructions:
- `git clone git@github.com:theodor96/cryptobox.git`
- `cd cryptobox`
- `./configure`
- `cd build && make && make install && cd ..`
- `cd bin`
- `./cryptobox`

About:
- offers an API to a cryptographic implementation of 3 basic operations:
  - generate a key
  - sign a message with a key
  - verify the signature of a message against a key
- the generated keys are protected via a carefully designed scheme using state-of-the-art algorithms:
  - secret material never leaves the `cryptobox` but instead a [BLAKE2 - RFC7693](https://tools.ietf.org/html/rfc7693) `BLAKE2s` 256 bit message digest of it is computed and used as its identifier.
  - for storage, the key is encrypted in an onion of two layers
  - first layer is an encryption via [PKCS#5 v2.0 - RFC 2898](https://tools.ietf.org/html/rfc2898) using `PBES2` for key derivation with `AES-256` in `CBC` mode. The result is a serialized (in `ASN.1` `DER` encoding) [PKCS#8 - RFC5208](https://tools.ietf.org/html/rfc5208) `EncryptedPrivateKeyInfo` structure.
  - the second layer takes the result of the first one and applies an authenticated encryption using the [ChaCha20-Poly1305 - RFC7539](https://tools.ietf.org/html/rfc7539) algorithm with a key also of 256 bits. The symmetric key and the IV fed to the stream cipher are derived by means of a [HKDF - RFC7539](https://tools.ietf.org/html/rfc7539) `HMAC-`[Keccak](https://en.wikipedia.org/wiki/SHA-3)`-384` extract-and-expand key derivation function.
  - the identifier (`BLAKE2s` hash) of the key is taken into account at this second layer in two ways: a) first it is used as the salt provided to the `HKDF` function b) it is integrity protected by being authenticated with `ChaCha20-Poly1305` as additional authenticated data. So that even if at some point a pseudo-preimage attack on `BLAKE2s` succeeds, a different key cannot be recovered unless it was truly the one for which that message digest had been computed.
  -  the initial derivation data used for `PBES2` as well as for `HKDF` is a user chosen passphrase with an `1024` bytes maximum length (backend limitation, in this case `OpenSSL`).
- as soon as a key is generated, it is two-layer-encrypted and saved on the disk. The user is given the handle of the key (its `BLAKE2s` digest) and the passphrase he chose.
- By means of the encryption scheme design, the handle and the passphrase, while simple primitives at first sight, make an extremely powerful mechanism because no information is leaked and nothing can be retrieved without the knowledge of both.
- for all subquential operations, the user will refer to a key via its handle and the `cryptobox` is responsible of retrieving the key if that shall be needed.
- verification of a signature can be done by providing the handle and the passphrase for a key and letting `cryptobox` retrieve it or it can be done by providing only the corresponding public part of the key that was used for signing. The public part is returned as well by the `cryptobox` in the first operation, `generate`.

Improvements todo:
- extract and offer cryptobox as a shared library
- perhaps a `conan` recipe for it would be nice too
- have the client as a different application

Features todo:
- offer multiple elliptic curve alternatives to `brainpoolP256r1`
- offer `EdDSA` as an alternative to `ECDSA`
- make `cryptobox` backend agnostic (`Botan` and `Crypto++` would be nice alternatives)

Code todo:
- C++ify the `OpenSSL` backend. Progress was made in that direction but a whole lot of splitting into several classes/files/functionalities can be done at that level.
- Unit testing

Documentation todo:
- write API documentation
- design decisions
