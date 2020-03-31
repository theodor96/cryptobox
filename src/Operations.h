#ifndef CRYPTOBOX_SRC_OPERATIONS_H
#define CRYPTOBOX_SRC_OPERATIONS_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Types.h"

#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox::operations
{
    KeyHandlePtr generateKey(const std::string& passphrase);

    SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle);

    bool verifySignature(const SignaturePtr& signature, const MessagePtr& message, const KeyHandlePtr& keyHandle);
}

#endif
