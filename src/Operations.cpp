#include "Operations.h"

#include "Buffer.h"
#include "KeyHandle.h"
#include "Message.h"
#include "Signature.h"

#include "OpenSsl.h"
#include <iostream>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    namespace operations
    {
        KeyHandlePtr generateKey(const std::string& passphrase)
        {
            return std::make_unique<KeyHandle>(getHexaFromBuffer(writeEvpPkey(generateEvpPkey(), passphrase)),
                                               passphrase);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle)
        {
            //return std::make_unique<Signature>(Buffer::createFromHex("abcdef010203040506070809"));


            auto xx = Buffer::createFromHex(keyHandle->getName());
            auto signature = signMessage(messageBuffer, readEvpPkey(::Buffer{xx.cbegin(), xx.cend()}, keyHandle->getPassphrase()));
            std::cout << "\n\nSignature computed = " << getHexaFromBuffer(signature);

        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        bool verifySignature(const SignaturePtr& signature,
                             const MessagePtr& message,
                             const KeyHandlePtr& keyHandle)
        {
            return false;
        }
    }
}
