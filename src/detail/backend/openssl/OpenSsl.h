#ifndef CRYPTOBOX_SRC_DETAIL_BACKEND_OPENSSL_OPENSSL_H
#define CRYPTOBOX_SRC_DETAIL_BACKEND_OPENSSL_OPENSSL_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Buffer.h"
#include "KeyHandle.h"
#include "Types.h"

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
#include <sstream>
#include <string>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constexpr int CHACHA20_AUTHN_TAG_SIZE = 16;
constexpr int CHACHA20_IV_SIZE = 12;
constexpr int CHACHA20_KEY_SIZE = 32;
constexpr int CSPRNG_SEED_LENGTH = 4096;
constexpr int EC_BRAINPOOLP256R1_KEY_SIZE = 32;
constexpr const char* KEY_STORAGE_PATH = "storage/keys";

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

std::string getFilenameFromKeyHandle(const cryptobox::KeyHandlePtr& keyHandle)
{
	// i'd love some base64 here but case insensitive filesystems wouldn't love it as much

	return KEY_STORAGE_PATH + std::string{"/"} + keyHandle->getName();
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

cryptobox::Buffer getPrivateKeyBuffer(EVP_PKEY* evpPkey)
{
	auto ecKey = EVP_PKEY_get0_EC_KEY(evpPkey);
	bail(nullptr != ecKey, "EVP_PKEY_get0_EC_KEY");

	auto privateKeyBn = EC_KEY_get0_private_key(ecKey);
	bail(nullptr != privateKeyBn, "EC_KEY_get0_private_key");

	auto privateKeyBnSize = BN_num_bytes(privateKeyBn);
	bail(EC_BRAINPOOLP256R1_KEY_SIZE == privateKeyBnSize, "BN_num_bytes");

    cryptobox::Buffer privateKeyBuffer(privateKeyBnSize);
	bail(privateKeyBuffer.getSize() == BN_bn2bin(privateKeyBn, privateKeyBuffer.getWriteableRawBuffer()), "BN_bn2bin");

	return privateKeyBuffer;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void seedCsprng()
{
    static bool csprngAlreadySeeded{false};
    if (!csprngAlreadySeeded)
    {
        bail(CSPRNG_SEED_LENGTH == RAND_load_file("/dev/random", CSPRNG_SEED_LENGTH), "RAND_load_file");
        csprngAlreadySeeded = true;
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EVP_PKEY* generateEvpPkey()
{
	auto evpPkeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    bail(nullptr != evpPkeyCtx, "EVP_PKEY_CTX_new_id");

    bail(EVP_PKEY_keygen_init(evpPkeyCtx), "EVP_PKEY_keygen_init");
    bail(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evpPkeyCtx, NID_brainpoolP256r1),
         "EVP_PKEY_CTX_set_ec_paramgen_curve_nid");

    seedCsprng();

    EVP_PKEY* evpPkey{};
    bail(EVP_PKEY_keygen(evpPkeyCtx, &evpPkey), "EVP_PKEY_keygen");
    bail(nullptr != evpPkey, "EVP_PKEY_keygen");

    EVP_PKEY_CTX_free(evpPkeyCtx);

    return evpPkey;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

cryptobox::Buffer deriveFromPassPhrase(const std::string& passphrase, const cryptobox::Buffer& saltData)
{
    auto evpPkeyContext = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    bail(nullptr != evpPkeyContext, "EVP_PKEY_CTX_new_id");

    bail(EVP_PKEY_derive_init(evpPkeyContext), "EVP_PKEY_derive_init");
    bail(EVP_PKEY_CTX_hkdf_mode(evpPkeyContext, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND), "EVP_PKEY_CTX_hkdf_mode");

    auto evpMdSha3 = EVP_sha3_384();
    bail(nullptr != evpMdSha3, "EVP_sha3_384");

    bail(EVP_PKEY_CTX_set_hkdf_md(evpPkeyContext, evpMdSha3), "EVP_PKEY_CTX_set_hkdf_md");

    bail(EVP_PKEY_CTX_set1_hkdf_salt(evpPkeyContext, saltData.getRawBuffer(), saltData.getSize()),
         "EVP_PKEY_CTX_set1_hkdf_salt");

    bail(EVP_PKEY_CTX_set1_hkdf_key(evpPkeyContext, passphrase.c_str(), passphrase.size()),
         "EVP_PKEY_CTX_set1_hkdf_key");

    cryptobox::Buffer derivationResult(CHACHA20_KEY_SIZE + CHACHA20_IV_SIZE);
    bail(derivationResult.getSize() <= EVP_MD_size(evpMdSha3), "wrong derivationResult size");

    auto derivationResultLength{derivationResult.getSize()};
    bail(EVP_PKEY_derive(evpPkeyContext, derivationResult.getWriteableRawBuffer(), &derivationResultLength),
         "EVP_PKEY_derive");

    bail(derivationResult.getSize() == derivationResultLength, "EVP_PKEY_derive");

    EVP_PKEY_CTX_free(evpPkeyContext);

    return derivationResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

cryptobox::Buffer getHashableDataFromEvpPkey(EVP_PKEY* evpPkey)
{
	auto evpPkeyEcIdentifier = EVP_PKEY_EC;
	auto nidBrainpoolp256r1Identifier = NID_brainpoolP256r1;

    cryptobox::Buffer keyMetadata(sizeof(evpPkeyEcIdentifier) + sizeof(nidBrainpoolp256r1Identifier));
	std::memcpy(keyMetadata.getWriteableRawBuffer(), &evpPkeyEcIdentifier, sizeof(evpPkeyEcIdentifier));
	std::memcpy(keyMetadata.getWriteableRawBuffer() + sizeof(evpPkeyEcIdentifier),
	            &nidBrainpoolp256r1Identifier,
	            sizeof(nidBrainpoolp256r1Identifier));

	keyMetadata.append(getPrivateKeyBuffer(evpPkey));

	return keyMetadata;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

cryptobox::Buffer computeKeyHandle(EVP_PKEY* evpPkey)
{
	auto evpMdCtx = EVP_MD_CTX_new();
	bail(nullptr != evpMdCtx, "EVP_MD_CTX_new");

	EVP_MD_CTX_set_flags(evpMdCtx,
	                     static_cast<unsigned int>(EVP_MD_CTX_FLAG_ONESHOT) |
	                                                               static_cast<unsigned int>(EVP_MD_CTX_FLAG_FINALISE));

	auto evpMdBlake2 = EVP_blake2s256();
	bail(nullptr != evpMdBlake2, "EVP_blake2s256");

	bail(EVP_DigestInit_ex(evpMdCtx, evpMdBlake2, nullptr), "EVP_DigestInit_ex");

	auto keyDataToHash = getHashableDataFromEvpPkey(evpPkey);
	bail(EVP_DigestUpdate(evpMdCtx, keyDataToHash.getRawBuffer(), keyDataToHash.getSize()), "EVP_DigestUpdate");

    cryptobox::Buffer keyHandleResult(EVP_MD_size(evpMdBlake2));

	unsigned int digestBytesWritten{};
	bail(EVP_DigestFinal_ex(evpMdCtx, keyHandleResult.getWriteableRawBuffer(), &digestBytesWritten),
	     "EVP_DigestFinal_ex");

	bail(keyHandleResult.getSize() == digestBytesWritten, "EVP_DigestFinal_ex");

	EVP_MD_CTX_free(evpMdCtx);

	return keyHandleResult
	;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


BIO* constructFileBio(const std::string& fileName, const std::string& openMode)
{
	auto fileBioMethod = BIO_s_file();
    bail(nullptr != fileBioMethod, "BIO_s_file");

   	auto fileBio = BIO_new(fileBioMethod);
   	bail(nullptr != fileBio, "BIO_new");

   	auto fileDescriptor = std::fopen(fileName.c_str(), openMode.c_str());
   	bail(nullptr != fileDescriptor, "std::fopen");
   	bail(BIO_set_fp(fileBio, fileDescriptor, BIO_CLOSE), "BIO_set_fp");

   	return fileBio;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


BIO* constructCipherBio(const cryptobox::Buffer& keyHandle, const std::string passphrase, int isEncryption)
{
   	auto cipherBioMethod = BIO_f_cipher();
    bail(nullptr != cipherBioMethod, "BIO_f_cipher");

   	auto cipherBio = BIO_new(cipherBioMethod);
   	bail(nullptr != cipherBio, "BIO_new");

   	auto evpCipherChacha20Poly1305 = EVP_chacha20_poly1305();
   	bail(nullptr != evpCipherChacha20Poly1305, "EVP_chacha20_poly1305");

   	auto derivation = deriveFromPassPhrase(passphrase, keyHandle);
   	auto key = Buffer(derivation.cbegin(), derivation.cbegin() + CHACHA20_KEY_SIZE);
   	bail(CHACHA20_KEY_SIZE == key.size(), "deriveFromPassPhrase");
   	auto iv = Buffer(derivation.cbegin() + CHACHA20_KEY_SIZE, derivation.cend());
   	bail(CHACHA20_IV_SIZE == iv.size(), "deriveFromPassPhrase");

   	bail(BIO_set_cipher(cipherBio, evpCipherChacha20Poly1305, key.data(), iv.data(), isEncryption), "bio_set_cipher");

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
   	bail(EVP_CIPHER_CTX_ctrl(evpCipherCtx,
   	                         EVP_CTRL_AEAD_GET_TAG,
   	                         authenticationTag.size(),
   	                         authenticationTag.data()),
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

EVP_CIPHER_CTX* getCipherCtxFromCipherBio(BIO* cipherBio)
{
   	EVP_CIPHER_CTX* evpCipherCtx{};
   	bail(BIO_get_cipher_ctx(cipherBio, &evpCipherCtx), "BIO_get_cipher_ctx");
    bail(nullptr != evpCipherCtx, "BIO_get_cipher_ctx");

    return evpCipherCtx;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer writeEvpPkey(EVP_PKEY* evpPkey, const std::string& passphrase)
{
	auto keyHandle = computeKeyHandle(evpPkey);
   	bail(KEY_HANDLE_SIZE == keyHandle.size(), "computeKeyHandle");

   	auto fileBio = constructFileBio(getFilenameFromKeyHandle(keyHandle), "wb");
   	auto cipherBio = constructCipherBio(keyHandle, passphrase, 1);

   	auto evpCipherCtx = getCipherCtxFromCipherBio(cipherBio);
    setAdditionalAuthenticatedData(evpCipherCtx, keyHandle);

   	bail(cipherBio == BIO_push(cipherBio, fileBio), "BIO_push");

	auto evpCipherAes256Cbc = EVP_aes_256_cbc();
	bail(nullptr != evpCipherAes256Cbc, "EVP_aes_256_cbc");

	bail(0 == BIO_seek(fileBio, CHACHA20_AUTHN_TAG_SIZE), "BIO_seek");
	bail(i2d_PKCS8PrivateKey_bio(cipherBio,
	                             evpPkey,
	                             evpCipherAes256Cbc,
	                             passphrase.c_str(),
	                             passphrase.size(),
	                             nullptr,
	                             nullptr),
	     "i2d_PKCS8PrivateKey_bio");

	triggerCipherFinal(evpCipherCtx);
   	auto authenticationTag = getAuthenticationTag(evpCipherCtx);

   	bail(0 == BIO_seek(fileBio, 0), "BIO_seek");
   	bail(authenticationTag.size() == BIO_write(fileBio, authenticationTag.data(), authenticationTag.size()),
   	     "BIO_write");

	BIO_free_all(cipherBio);

	return keyHandle;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


EVP_PKEY* readEvpPkey(const Buffer& keyHandle, const std::string& passphrase)
{
   	bail(KEY_HANDLE_SIZE == keyHandle.size(), "wrong keyHandle size");

   	auto fileBio = constructFileBio(getFilenameFromKeyHandle(keyHandle), "rb");
   	auto cipherBio = constructCipherBio(keyHandle, passphrase, 0);

    Buffer authenticationTag(CHACHA20_AUTHN_TAG_SIZE);
    bail(authenticationTag.size() == BIO_read(fileBio, authenticationTag.data(), authenticationTag.size()), "BIO_read");
    
    auto evpCipherCtx = getCipherCtxFromCipherBio(cipherBio);
    setAdditionalAuthenticatedData(evpCipherCtx, keyHandle);
    setAuthenticationTag(evpCipherCtx, authenticationTag);
    
    bail(cipherBio == BIO_push(cipherBio, fileBio), "BIO_push");

   	EVP_PKEY* keyResult{};
	bail(nullptr != d2i_PKCS8PrivateKey_bio(cipherBio,
		                     			    &keyResult,
		                         			[](char* outputBuffer, int outputBufferLength, int, void* userData) -> int
		                         			{
		                         				auto passphrase = *reinterpret_cast<const std::string*>(userData);
		                         				std::strncpy(outputBuffer, passphrase.c_str(), outputBufferLength);
		                         				return passphrase.size();
		                         			},
		                         			&const_cast<std::string&>(passphrase)),
	     "d2i_PKCS8PrivateKey_bio");

	triggerCipherFinal(evpCipherCtx);

   	BIO_free_all(cipherBio);

	return keyResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

EVP_MD_CTX* constructSha3EvpMd(EVP_PKEY* evpPkey, int isSigning)
{
	auto evpMdCtx = EVP_MD_CTX_new();
	bail(nullptr != evpMdCtx, "EVP_MD_CTX_new");

    EVP_MD_CTX_set_flags(evpMdCtx,
                         static_cast<unsigned int>(EVP_MD_CTX_FLAG_ONESHOT) |
                                                                   static_cast<unsigned int>(EVP_MD_CTX_FLAG_FINALISE));

	auto evpMdSha3 = EVP_sha3_256();
	bail(nullptr != evpMdSha3, "EVP_sha3_256");

	auto digestInitFunction = isSigning ? EVP_DigestSignInit : EVP_DigestVerifyInit;
	bail(digestInitFunction(evpMdCtx, nullptr, evpMdSha3, nullptr, evpPkey),
	     isSigning ? "EVP_DigestSignInit" : "EVP_DigestVerifyInit");

	return evpMdCtx;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

Buffer signMessage(const Buffer& message, EVP_PKEY* evpPkey)
{
	auto evpMdCtx = constructSha3EvpMd(evpPkey, 1);

	std::size_t signatureLength{};
	bail(EVP_DigestSign(evpMdCtx, nullptr, &signatureLength, message.data(), message.size()), "EVP_DigestSign");
	bail(0 < signatureLength, "EVP_DigestSign");

	Buffer signatureResult(signatureLength);
	bail(EVP_DigestSign(evpMdCtx, signatureResult.data(), &signatureLength, message.data(), message.size()),
	     "EVP_DigestSign");

	signatureResult.resize(signatureLength);

	EVP_MD_CTX_free(evpMdCtx);

	return signatureResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool verifySignature(const Buffer& message, const Buffer& signature, EVP_PKEY* evpPkey)
{
	auto evpMdCtx = constructSha3EvpMd(evpPkey, 0);

	auto verifyResult = EVP_DigestVerify(evpMdCtx, signature.data(), signature.size(), message.data(), message.size());
	bail(0 <= verifyResult, "EVP_DigestVerify");

	EVP_MD_CTX_free(evpMdCtx);

	return verifyResult;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/*
int main()
{
	auto evpPkey = generateEvpPkey();
	std::cout << "\n\nKey generated = " << getHexaFromBuffer(getPrivateKeyBuffer(evpPkey));

	auto messageToBeSigned = std::string{"Message to be signed with ECDSA using the elliptic curve brainpoolP256r1"};
	auto messageBuffer = Buffer{messageToBeSigned.cbegin(), messageToBeSigned.cend()};

	auto signature = signMessage(messageBuffer, evpPkey);
	std::cout << "\n\nSignature computed = " << getHexaFromBuffer(signature);

	auto keyHandle = writeEvpPkey(evpPkey, "myVerySecretPassPhrase");
	std::cout << "\n\nKey written successfully, handle = " << getHexaFromBuffer(keyHandle);

	evpPkey = readEvpPkey(keyHandle, "myVerySecretPassPhrase");
	std::cout << "\n\nKey read back successfully, key = " << getHexaFromBuffer(getPrivateKeyBuffer(evpPkey));

	auto verifyResult = verifySignature(messageBuffer, signature, evpPkey);
	std::cout << "\n\nSignature verification result = " << verifyResult << "\n\n\n" << std::flush;

	return 0;
}
*/

#endif
