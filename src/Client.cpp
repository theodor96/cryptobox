#include "Buffer.h"
#include "KeyHandle.h"
#include "Message.h"
#include "Operations.h"
#include "Signature.h"

#include <iostream>
#include <memory>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constexpr int BULK_ITERATIONS_COUNT = 1;
constexpr const char* KEY_PASSPHRASE = "my very secret passphrase";
constexpr const char* MESSAGE_TO_SIGN = "some message I intend to sign with ECDSA via brainpoolp256r1";
constexpr const char* SPECIFIC_PUBLIC_KEY_HEX = "";
constexpr const char* SPECIFIC_VALID_SIGNATURE_HEX = "";
constexpr const char* SPECIFIC_INVALID_SIGNATURE_HEX = "";

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class CryptoboxClient
{
public:
    CryptoboxClient()
    : r_message{std::make_unique<cryptobox::Message>(cryptobox::Buffer::createFromText(MESSAGE_TO_SIGN))}
    {

    }

    void testBulk() const
    {
        for (auto itr = 0; itr < BULK_ITERATIONS_COUNT; ++itr)
        {
            auto keyHandle = cryptobox::operations::generateKey(KEY_PASSPHRASE + std::to_string(itr));
            std::cout << "\n\ntestBulk: cryptobox generated key with name = "
                      << keyHandle->getName()
                      << ", passphrase = "
                      << keyHandle->getPassphrase();

            auto signature = cryptobox::operations::signMessage(r_message, keyHandle);
            std::cout << "\n\ntestBulk: cryptobox produced signature = "
                      << signature->getBuffer().toHex()
                      << ", for message = "
                      << r_message->getBuffer().toHex();

            auto isSignatureValid = cryptobox::operations::verifySignature(signature, r_message, keyHandle);
            std::cout << "\n\ntestBulk: cryptobox attempted to verify the given signature, result = "
                      << isSignatureValid;
        }
    }

    void testSpecifics() const
    {
        auto keyHandle = std::make_unique<cryptobox::KeyHandle>(
                                                             cryptobox::Buffer::createFromHex(SPECIFIC_PUBLIC_KEY_HEX));

        auto validSignature = std::make_unique<cryptobox::Signature>(
                                                        cryptobox::Buffer::createFromHex(SPECIFIC_VALID_SIGNATURE_HEX));
        auto isValidSignatureValid = cryptobox::operations::verifySignature(validSignature, r_message, keyHandle);
        std::cout << "\n\ntestSpecifics: cryptobox attempted to verify specific valid signature, result = "
                  << isValidSignatureValid;

        auto invalidSignature = std::make_unique<cryptobox::Signature>(
                                                      cryptobox::Buffer::createFromHex(SPECIFIC_INVALID_SIGNATURE_HEX));
        auto isInvalidSignatureValid = cryptobox::operations::verifySignature(invalidSignature, r_message, keyHandle);
        std::cout << "\n\ntestSpecifics: cryptobox attempted to verify specific invalid signature, result = "
                  << isInvalidSignatureValid;
    }

private:
    cryptobox::MessagePtr r_message;
};

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main()
{
    CryptoboxClient cryptoboxClient{};

    cryptoboxClient.testBulk();
    cryptoboxClient.testSpecifics();

    std::cout << "\n" << std::endl;

    return 0;
}
