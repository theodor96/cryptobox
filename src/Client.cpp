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

    constexpr const char* SPECIFIC_PUBLIC_KEY_HEX = "5eee58f650e1c834be271c7311ff36200ce4ec990fc5158089b93e994861c1c29d"
                                                    "92a0ee458d85cef0f48f77cb669dbe2bc6cf4aa358bcdcadeed7135adc3a19";

    constexpr const char* SPECIFIC_VALID_SIGNATURE_HEX = "304402202d8cf06b2d06ad6db495e92def8af3311a58d94d3ab24ead49be8"
                                                         "428385cb8d20220173ba3b9832796ff40914b538803f719d67812705ad847"
                                                         "e379321ff5194b035f";

    constexpr const char* SPECIFIC_INVALID_SIGNATURE_HEX = "304402202d8cf06b2d06ad6db495e92def8af3311a58d94d3ab24ead49b"
                                                           "e8428385cb8d20220173ba3b9832796ff40914b538803f719d67812705a"
                                                           "d847e379321ff5194b035e"; // last digit changed
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
