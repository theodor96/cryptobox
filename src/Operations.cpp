#include "Operations.h"

#include "Buffer.h"
#include "KeyHandle.h"
#include "Message.h"
#include "Signature.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    namespace operations
    {
        KeyHandlePtr generateKey(const std::string& passphrase)
        {
            std::string keyName{"someNiceKeyName"};
            return std::make_unique<KeyHandle>(keyName, passphrase);
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle)
        {
            return std::make_unique<Signature>(Buffer::createFromHex("abcdef010203040506070809"));
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
