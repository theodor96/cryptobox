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
        auto [keyHandleName, publicKey] = writeEvpPkey(generateEvpPkey(), passphrase);

        auto keyHandle = std::make_unique<KeyHandle>(keyHandleName, passphrase);

        // do not set the public key such that key will be re-read from storage upon signature verification
        //
        // keyHandle->setPublicKey(Buffer::createFromInternalBuffer(publicKey));
        static_cast<void>(publicKey);

        return keyHandle;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle)
    {
        return std::make_unique<Signature>(Buffer::createFromInternalBuffer(
                                                    signMessage(message->getBuffer().getInternalBuffer(),
                                                                readEvpPkey(Buffer::createFromHex(keyHandle->getName()).
                                                                                                    getInternalBuffer(),
                                                                            keyHandle->getPassphrase()))));
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool verifySignature(const SignaturePtr& signature, const MessagePtr& message, const KeyHandlePtr& keyHandle)
    {
        if (keyHandle->hasPublicKey())
        {
            auto publicKey = getEvpPkeyFromPublicKeyBuffer(keyHandle->getPublicKey().getInternalBuffer());

            return verifySignature(message->getBuffer().getInternalBuffer(),
                                   signature->getBuffer().getInternalBuffer(),
                                   publicKey.get());
        }

        return verifySignature(message->getBuffer().getInternalBuffer(),
                               signature->getBuffer().getInternalBuffer(),
                               readEvpPkey(Buffer::createFromHex(keyHandle->getName()).getInternalBuffer(),
                                           keyHandle->getPassphrase()));

    }
}
