////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "CryptoBoxService.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "KeyHandle.h"
#include "Message.h"
#include "Signature.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    CryptoBoxService::KeyHandlePtr CryptoBoxService::generateKey(const std::string& passPhrase)
    {
        return {};
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    CryptoBoxService::SignaturePtr CryptoBoxService::signMessage(const MessagePtr& message,
                                                                 const KeyHandlePtr& keyHandle)
    {
        return {};
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool CryptoBoxService::verifySignature(const SignaturePtr& signature,
                                           const MessagePtr& message,
                                           const KeyHandlePtr& keyHandle)
    {
        return {};
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
