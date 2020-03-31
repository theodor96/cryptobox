#include "Operations.h"

#include "Buffer.h"
#include "KeyHandle.h"
#include "Message.h"
#include "Signature.h"
#include "detail/backend/openssl/OpenSsl.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox::operations
{
    KeyHandlePtr generateKey(const std::string& passphrase)
    {
        return std::make_unique<KeyHandle>(getHexaFromBuffer(writeEvpPkey(generateEvpPkey(), passphrase)), passphrase);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle)
    {
        auto buffer = Buffer::createFromHex(keyHandle->getName());
        auto signature = signMessage(::Buffer{message->getBuffer().getRawBuffer(),
                                              message->getBuffer().getRawBuffer() + message->getBuffer().getSize()},
                                     readEvpPkey(::Buffer{buffer.getRawBuffer(),
                                                          buffer.getRawBuffer() + buffer.getSize()},
                                     keyHandle->getPassphrase()));

        return std::make_unique<Signature>(Buffer::createFromRawBuffer(signature.data(), signature.size()));

    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool verifySignature(const SignaturePtr& signature, const MessagePtr& message, const KeyHandlePtr& keyHandle)
    {
        evpPkey = readEvpPkey(keyHandle, "myVerySecretPassphrase");
        std::cout << "\n\nKey read back successfully, key = " << getHexaFromBuffer(getPrivateKeyBuffer(evpPkey));

        auto verifyResult = verifySignature(messageBuffer, signature, evpPkey);
        std::cout << "\n\nSignature verification result = " << verifyResult << "\n\n\n" << std::flush;
    }
}
