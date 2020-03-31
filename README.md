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