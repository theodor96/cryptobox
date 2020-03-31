#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

using Buffer = std::vector<unsigned char>;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    constexpr int EC_BRAINPOOLP256R1_KEY_SIZE = 32;
    constexpr int CHACHA20_AUTHN_TAG_SIZE = 16;
    constexpr int CHACHA20_IV_SIZE = 12;
    constexpr int CHACHA20_KEY_SIZE = 32;
    constexpr int CSPRNG_SEED_LENGTH = 4096;
    constexpr int HEX_BYTE_MINIMUM_WIDTH = 2;
    constexpr int KEY_HANDLE_SIZE = 32;
    constexpr const char* KEY_STORAGE_PATH = "storage/keys";

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    using BigNumPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
    using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void bail(int status, const std::string& errorMessage)
{
    if (1 != status)
    {
        std::cout << "\n\n" << errorMessage << "\n\n" << std::flush;
        abort();
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::string getHexaFromBuffer(const Buffer& data)
{
    std::ostringstream stream{};
    stream << std::hex;

    for (const auto& itr : data)
    {
        stream << std::hex << std::setfill('0') << std::setw(HEX_BYTE_MINIMUM_WIDTH) << static_cast<int>(itr);
    }

    return stream.str();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::string getFilenameFromKeyHandle(const Buffer& keyHandle)
{
    // i'd love some base64 here but case insensitive filesystems wouldn't love it as much

    return KEY_STORAGE_PATH + std::string{"/"} + getHexaFromBuffer(keyHandle);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EC_KEY* getEcKeyFromEvpPkey(EVP_PKEY* evpPkey)
{
    auto ecKey = EVP_PKEY_get0_EC_KEY(evpPkey);
    bail(nullptr != ecKey, "EVP_PKEY_get0_EC_KEY");

    return ecKey;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer getPrivateKeyBuffer(EVP_PKEY* evpPkey)
{
    auto privateKeyBn = EC_KEY_get0_private_key(getEcKeyFromEvpPkey(evpPkey));
    bail(nullptr != privateKeyBn, "EC_KEY_get0_private_key");

    auto privateKeyBnSize = BN_num_bytes(privateKeyBn);
    bail(EC_BRAINPOOLP256R1_KEY_SIZE == privateKeyBnSize, "BN_num_bytes");

    Buffer privateKeyBuffer(privateKeyBnSize);
    bail(privateKeyBuffer.size() == BN_bn2bin(privateKeyBn, privateKeyBuffer.data()), "BN_bn2bin");

    return privateKeyBuffer;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer getPublicKeyBuffer(EVP_PKEY* evpPkey)
{
    auto ecKey = getEcKeyFromEvpPkey(evpPkey);
    auto publicKey = EC_KEY_get0_public_key(ecKey);
    bail(nullptr != publicKey, "EC_KEY_get0_public_key");

    BigNumPtr xCoordBn{BN_new(), BN_free};
    bail(nullptr != xCoordBn, "BN_new");

    BigNumPtr yCoordBn{BN_new(), BN_free};
    bail(nullptr != yCoordBn, "BN_new");

    bail(EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ecKey), publicKey, xCoordBn.get(), yCoordBn.get(), nullptr),
         "EC_POINT_get_affine_coordinates");

    Buffer xCoordBuffer(EC_BRAINPOOLP256R1_KEY_SIZE);
    bail(xCoordBuffer.size() == BN_bn2binpad(xCoordBn.get(), xCoordBuffer.data(), xCoordBuffer.size()), "BN_bn2binpad");

    Buffer yCoordBuffer(EC_BRAINPOOLP256R1_KEY_SIZE);
    bail(xCoordBuffer.size() == BN_bn2binpad(yCoordBn.get(), yCoordBuffer.data(), yCoordBuffer.size()), "BN_bn2binpad");

    xCoordBuffer.insert(xCoordBuffer.end(), yCoordBuffer.cbegin(), yCoordBuffer.cend());
    return xCoordBuffer;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EVP_PKEY* generateEvpPkey()
{
    EvpPkeyCtxPtr evpPkeyCtx{EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free};
    bail(nullptr != evpPkeyCtx, "EVP_PKEY_CTX_new_id");

    bail(EVP_PKEY_keygen_init(evpPkeyCtx.get()), "EVP_PKEY_keygen_init");
    bail(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evpPkeyCtx.get(), NID_brainpoolP256r1),
         "EVP_PKEY_CTX_set_ec_paramgen_curve_nid");

    bail(CSPRNG_SEED_LENGTH == RAND_load_file("/dev/random", CSPRNG_SEED_LENGTH), "RAND_load_file");

    EVP_PKEY* evpPkey{};
    bail(EVP_PKEY_keygen(evpPkeyCtx.get(), &evpPkey), "EVP_PKEY_keygen");
    bail(nullptr != evpPkey, "EVP_PKEY_keygen");

    return evpPkey;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer deriveFromPassphrase(const std::string& passphrase, const Buffer& saltData)
{
    EvpPkeyCtxPtr evpPkeyCtx{EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr), EVP_PKEY_CTX_free};
    bail(nullptr != evpPkeyCtx, "EVP_PKEY_CTX_new_id");

    bail(EVP_PKEY_derive_init(evpPkeyCtx.get()), "EVP_PKEY_derive_init");
    bail(EVP_PKEY_CTX_hkdf_mode(evpPkeyCtx.get(), EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND), "EVP_PKEY_CTX_hkdf_mode");

    auto evpMdSha3 = EVP_sha3_384();
    bail(nullptr != evpMdSha3, "EVP_sha3_384");

    bail(EVP_PKEY_CTX_set_hkdf_md(evpPkeyCtx.get(), evpMdSha3), "EVP_PKEY_CTX_set_hkdf_md");
    bail(EVP_PKEY_CTX_set1_hkdf_salt(evpPkeyCtx.get(),
                                     saltData.data(),
                                     saltData.size()),
         "EVP_PKEY_CTX_set1_hkdf_salt");
    bail(EVP_PKEY_CTX_set1_hkdf_key(evpPkeyCtx.get(), passphrase.c_str(), passphrase.size()),
         "EVP_PKEY_CTX_set1_hkdf_key");

    Buffer derivationResult(CHACHA20_KEY_SIZE + CHACHA20_IV_SIZE);
    bail(derivationResult.size() <= EVP_MD_size(evpMdSha3), "wrong derivationResult size");

    auto derivationResultLength{derivationResult.size()};
    bail(EVP_PKEY_derive(evpPkeyCtx.get(), derivationResult.data(), &derivationResultLength), "EVP_PKEY_derive");
    bail(derivationResult.size() == derivationResultLength, "EVP_PKEY_derive");

    return derivationResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer getHashableDataFromEvpPkey(EVP_PKEY* evpPkey)
{
    auto evpPkeyEcIdentifier = EVP_PKEY_EC;
    auto nidBrainpoolp256r1Identifier = NID_brainpoolP256r1;

    Buffer keyMetadata(sizeof(evpPkeyEcIdentifier) + sizeof(nidBrainpoolp256r1Identifier));
    std::memcpy(keyMetadata.data(), &evpPkeyEcIdentifier, sizeof(evpPkeyEcIdentifier));
    std::memcpy(keyMetadata.data() + sizeof(evpPkeyEcIdentifier),
                &nidBrainpoolp256r1Identifier,
                sizeof(nidBrainpoolp256r1Identifier));

    auto privateKeyBuffer = getPrivateKeyBuffer(evpPkey);
    keyMetadata.insert(keyMetadata.end(), privateKeyBuffer.cbegin(), privateKeyBuffer.cend());

    return keyMetadata;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer computeKeyHandle(EVP_PKEY* evpPkey)
{
    EvpMdCtxPtr evpMdCtx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    bail(nullptr != evpMdCtx, "EVP_MD_CTX_new");

    EVP_MD_CTX_set_flags(evpMdCtx.get(), EVP_MD_CTX_FLAG_ONESHOT | EVP_MD_CTX_FLAG_FINALISE);

    auto evpMdBlake2 = EVP_blake2s256();
    bail(nullptr != evpMdBlake2, "EVP_blake2s256");

    bail(EVP_DigestInit_ex(evpMdCtx.get(), evpMdBlake2, nullptr), "EVP_DigestInit_ex");

    auto keyDataToHash = getHashableDataFromEvpPkey(evpPkey);
    bail(EVP_DigestUpdate(evpMdCtx.get(), keyDataToHash.data(), keyDataToHash.size()), "EVP_DigestUpdate");

    bail(KEY_HANDLE_SIZE == EVP_MD_size(evpMdBlake2), "EVP_MD_size");
    Buffer keyHandleResult(KEY_HANDLE_SIZE);

    unsigned int digestBytesWritten{};
    bail(EVP_DigestFinal_ex(evpMdCtx.get(), keyHandleResult.data(), &digestBytesWritten), "EVP_DigestFinal_ex");
    bail(keyHandleResult.size() == digestBytesWritten, "EVP_DigestFinal_ex");

    return keyHandleResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BioPtr constructFileBio(const std::string& fileName, const std::string& openMode)
{
    auto fileBioMethod = BIO_s_file();
    bail(nullptr != fileBioMethod, "BIO_s_file");

    BioPtr fileBio{BIO_new(fileBioMethod), BIO_free};
    bail(nullptr != fileBio, "BIO_new");

    auto fileDescriptor = std::fopen(fileName.c_str(), openMode.c_str());
    bail(nullptr != fileDescriptor, "std::fopen");
    bail(BIO_set_fp(fileBio.get(), fileDescriptor, BIO_CLOSE), "BIO_set_fp");

    return fileBio;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BioPtr constructCipherBio(const Buffer& keyHandle, const std::string& passphrase, int isEncryption)
{
    auto cipherBioMethod = BIO_f_cipher();
    bail(nullptr != cipherBioMethod, "BIO_f_cipher");

    BioPtr cipherBio{BIO_new(cipherBioMethod), BIO_free};
    bail(nullptr != cipherBio, "BIO_new");

    auto evpCipherChacha20Poly1305 = EVP_chacha20_poly1305();
    bail(nullptr != evpCipherChacha20Poly1305, "EVP_chacha20_poly1305");

    auto derivation = deriveFromPassphrase(passphrase, keyHandle);
    auto key = Buffer(derivation.cbegin(), derivation.cbegin() + CHACHA20_KEY_SIZE);
    bail(CHACHA20_KEY_SIZE == key.size(), "deriveFromPassphrase");
    auto iv = Buffer(derivation.cbegin() + CHACHA20_KEY_SIZE, derivation.cend());
    bail(CHACHA20_IV_SIZE == iv.size(), "deriveFromPassphrase");

    bail(BIO_set_cipher(cipherBio.get(), evpCipherChacha20Poly1305, key.data(), iv.data(), isEncryption),
         "bio_set_cipher");

    return cipherBio;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void setAdditionalAuthenticatedData(EVP_CIPHER_CTX* evpCipherCtx, const Buffer& keyHandle)
{
    int aadBytesWritten{};
    bail(EVP_CipherUpdate(evpCipherCtx, nullptr, &aadBytesWritten, keyHandle.data(), keyHandle.size()),
         "EVP_CipherUpdate");

    bail(keyHandle.size() == aadBytesWritten, "EVP_CipherUpdate");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void triggerCipherFinal(EVP_CIPHER_CTX* evpCipherCtx)
{
    Buffer outBuff{};
    int outBuffWritten{};
    bail(EVP_CipherFinal_ex(evpCipherCtx, outBuff.data(), &outBuffWritten), "EVP_CipherFinal");
    bail(0 == outBuffWritten, "EVP_CipherFinal");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer getAuthenticationTag(EVP_CIPHER_CTX* evpCipherCtx)
{
    Buffer authenticationTag(CHACHA20_AUTHN_TAG_SIZE);
    bail(EVP_CIPHER_CTX_ctrl(evpCipherCtx, EVP_CTRL_AEAD_GET_TAG, authenticationTag.size(), authenticationTag.data()),
         "EVP_CIPHER_CTX_ctrl");

    return authenticationTag;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void setAuthenticationTag(EVP_CIPHER_CTX* evpCipherCtx, Buffer& authenticationTag)
{
    bail(EVP_CIPHER_CTX_ctrl(evpCipherCtx, EVP_CTRL_AEAD_SET_TAG, authenticationTag.size(), authenticationTag.data()),
         "EVP_CIPHER_CTX_ctrl");
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EVP_CIPHER_CTX* getCipherCtxFromCipherBio(const BioPtr& cipherBio)
{
    EVP_CIPHER_CTX* evpCipherCtx{};
    bail(BIO_get_cipher_ctx(cipherBio.get(), &evpCipherCtx), "BIO_get_cipher_ctx");
    bail(nullptr != evpCipherCtx, "BIO_get_cipher_ctx");

    return evpCipherCtx;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

std::tuple<std::string, Buffer> writeEvpPkey(EVP_PKEY* evpPkey, const std::string& passphrase)
{
    auto keyHandle = computeKeyHandle(evpPkey);
    bail(KEY_HANDLE_SIZE == keyHandle.size(), "computeKeyHandle");

    auto fileBio = constructFileBio(getFilenameFromKeyHandle(keyHandle), "wb");
    auto cipherBio = constructCipherBio(keyHandle, passphrase, 1);

    auto evpCipherCtx = getCipherCtxFromCipherBio(cipherBio);
    setAdditionalAuthenticatedData(evpCipherCtx, keyHandle);

    bail(cipherBio.get() == BIO_push(cipherBio.get(), fileBio.get()), "BIO_push");

    auto evpCipherAes256Cbc = EVP_aes_256_cbc();
    bail(nullptr != evpCipherAes256Cbc, "EVP_aes_256_cbc");

    bail(0 == BIO_seek(fileBio.get(), CHACHA20_AUTHN_TAG_SIZE), "BIO_seek");
    bail(i2d_PKCS8PrivateKey_bio(cipherBio.get(),
                                 evpPkey,
                                 evpCipherAes256Cbc,
                                 passphrase.c_str(),
                                 passphrase.size(),
                                 nullptr,
                                 nullptr),
         "i2d_PKCS8PrivateKey_bio");

    triggerCipherFinal(evpCipherCtx);
    auto authenticationTag = getAuthenticationTag(evpCipherCtx);

    bail(0 == BIO_seek(fileBio.get(), 0), "BIO_seek");
    bail(authenticationTag.size() == BIO_write(fileBio.get(), authenticationTag.data(), authenticationTag.size()),
         "BIO_write");

    return std::make_tuple(getHexaFromBuffer(keyHandle), getPublicKeyBuffer(evpPkey));
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EVP_PKEY* readEvpPkey(const Buffer& keyHandle, const std::string& passphrase)
{
    bail(KEY_HANDLE_SIZE == keyHandle.size(), "wrong keyHandle size");

    auto fileBio = constructFileBio(getFilenameFromKeyHandle(keyHandle), "rb");
    auto cipherBio = constructCipherBio(keyHandle, passphrase, 0);

    Buffer authenticationTag(CHACHA20_AUTHN_TAG_SIZE);
    bail(authenticationTag.size() == BIO_read(fileBio.get(), authenticationTag.data(), authenticationTag.size()),
         "BIO_read");

    auto evpCipherCtx = getCipherCtxFromCipherBio(cipherBio);
    setAdditionalAuthenticatedData(evpCipherCtx, keyHandle);
    setAuthenticationTag(evpCipherCtx, authenticationTag);

    bail(cipherBio.get() == BIO_push(cipherBio.get(), fileBio.get()), "BIO_push");

    EVP_PKEY* keyResult{};
    bail(nullptr != d2i_PKCS8PrivateKey_bio(cipherBio.get(),
                                            &keyResult,
                                            [](char* outputBuffer, int outputBufferSize, int, void* userData) -> int
                                            {
                                                auto passphrase = *reinterpret_cast<const std::string*>(userData);
                                                std::strncpy(outputBuffer, passphrase.c_str(), outputBufferSize);

                                                return passphrase.size();
                                            },
                                            &const_cast<std::string&>(passphrase)),
         "d2i_PKCS8PrivateKey_bio");

    triggerCipherFinal(evpCipherCtx);

    return keyResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EvpMdCtxPtr constructSha3EvpMd(EVP_PKEY* evpPkey, int isSigning)
{
    EvpMdCtxPtr evpMdCtx{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    bail(nullptr != evpMdCtx, "EVP_MD_CTX_new");

    EVP_MD_CTX_set_flags(evpMdCtx.get(), EVP_MD_CTX_FLAG_ONESHOT | EVP_MD_CTX_FLAG_FINALISE);

    auto evpMdSha3 = EVP_sha3_256();
    bail(nullptr != evpMdSha3, "EVP_sha3_256");

    auto digestInitFunction = isSigning ? EVP_DigestSignInit : EVP_DigestVerifyInit;
    bail(digestInitFunction(evpMdCtx.get(), nullptr, evpMdSha3, nullptr, evpPkey),
         isSigning ? "EVP_DigestSignInit" : "EVP_DigestVerifyInit");

    return evpMdCtx;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer signMessage(const Buffer& message, EVP_PKEY* evpPkey)
{
    auto evpMdCtx = constructSha3EvpMd(evpPkey, 1);

    std::size_t signatureLength{};
    bail(EVP_DigestSign(evpMdCtx.get(), nullptr, &signatureLength, message.data(), message.size()), "EVP_DigestSign");
    bail(0 < signatureLength, "EVP_DigestSign");

    Buffer signatureResult(signatureLength);
    bail(EVP_DigestSign(evpMdCtx.get(), signatureResult.data(), &signatureLength, message.data(), message.size()),
         "EVP_DigestSign");
    signatureResult.resize(signatureLength);

    return signatureResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool verifySignature(const Buffer& message, const Buffer& signature, EVP_PKEY* evpPkey)
{
    auto evpMdCtx = constructSha3EvpMd(evpPkey, 0);

    auto verifyResult = EVP_DigestVerify(evpMdCtx.get(),
                                         signature.data(),
                                         signature.size(),
                                         message.data(),
                                         message.size());
    bail(0 <= verifyResult, "EVP_DigestVerify");

    return verifyResult;
}
