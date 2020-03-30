#include "Operations.h"

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
            return {};
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle)
        {
            return {};
        }

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        bool verifySignature(const SignaturePtr& signature,
                             const MessagePtr& message,
                             const KeyHandlePtr& keyHandle)
        {
            return {};
        }
    }

}
