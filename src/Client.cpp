#include "All.h"

#include <iostream>
#include <memory>
#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

constexpr int BULK_ITERATIONS_COUNT = 3;
constexpr const char* KEY_PASSPHRASE = "my very secret passphrase";
constexpr const char* MESSAGE_TO_SIGN = "some message I intend to sign with ECDSA via brainpoolp256r1";
constexpr const char* SPECIFIC_PUBLIC_KEY_HEX = "076749c95e492622aa8999356058466837909468a1b8a938c54f393a29d7d55f7247689f63cdf79c61d2001f92826642c7021f48cc95da88d2f3582c90ba6a61";
constexpr const char* SPECIFIC_VALID_SIGNATURE_HEX = "304502203720e535b946c4edb10ce722ddf0fd9d90a95a8dc2447102835a484ced56e740022100a9483697cd1abe3b89f5ff133fe7db98dc85d38c5715002245200430ddb3952a";
constexpr const char* SPECIFIC_INVALID_SIGNATURE_HEX = "304502203720e535b946c4edb10ce722ddf0fd9d90a95a8dc2447102835a484ced56e740022100a9483697cd1abe3b89f5ff133fe7db98dc85d38c5715002245200430ddb3952b";

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
