#include "All.h"

#include <iostream>
#include <exception>
#include <memory>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace
{
    constexpr int BULK_ITERATIONS_COUNT = 3;
    constexpr const char* KEY_PASSPHRASE = "my very secret passphrase";
    constexpr const char* MESSAGE_TO_SIGN = "some message to be signed with ECDSA via brainpoolp256r1";

    constexpr const char* SPECIFIC_PUBLIC_KEY_HEX = "76af84267752a731424b798faba4c5778ec40d1fccc6835a3e322db42db525505d"
                                                    "c93d93468d0017a418c19446410fce766c7a403d7ad1e52a1bc1bf8ecc6081";

    constexpr const char* SPECIFIC_VALID_SIGNATURE_HEX = "30440220102443fd266c93a6d2731e71ddc1178d18b55b540e4143df97f"
                                                         "f9123d401510302201ca0e031e42fa9a968a5a52b55bdda14303d480555"
                                                         "b07b27cb4120dc6851f4c7";

    constexpr const char* SPECIFIC_INVALID_SIGNATURE_HEX = "30440220102443fd266c93a6d2731e71ddc1178d18b55b540e4143df97f"
                                                           "f9123d401510302201ca0e031e42fa9a968a5a52b55bdda14303d480555"
                                                           "b07b27cb4120dc6851f4c6"; // last digit changed
}

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
            try
            {
                auto keyHandle = cryptobox::operations::generateKey(KEY_PASSPHRASE + std::to_string(itr));
                std::cout << "\n\ntestBulk: cryptobox generated key with name = "
                          << keyHandle->getName()
                          << "\n                             and passphrase = "
                          << keyHandle->getPassphrase();

                auto signature = cryptobox::operations::signMessage(r_message, keyHandle);
                std::cout << "\n\ntestBulk: cryptobox produced signature = "
                          << signature->getBuffer().toHex()
                          << "\n                           for message = "
                          << r_message->getBuffer().toHex();

                auto isSignatureValid = cryptobox::operations::verifySignature(signature, r_message, keyHandle);
                std::cout << "\n\ntestBulk: cryptobox attempted to verify the given signature, result = "
                          << isSignatureValid;
            }
            catch (const std::exception& ex)
            {
                std::cout << "\n\nException: " << ex.what() << std::flush;
            }

        }
    }

    void testSpecifics() const
    {
        try
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
            auto isInvalidSignatureValid = cryptobox::operations::verifySignature(invalidSignature,
                                                                                  r_message,
                                                                                  keyHandle);
            std::cout << "\n\ntestSpecifics: cryptobox attempted to verify specific invalid signature, result = "
                      << isInvalidSignatureValid;
        }
        catch (const std::exception& ex)
        {
            std::cout << "\n\nException: " << ex.what() << std::flush;
        }
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

    std::cout << "\n\n" << std::flush;

    return 0;
}
