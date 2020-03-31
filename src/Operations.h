#ifndef CRYPTOBOX_SRC_OPERATIONS_H
#define CRYPTOBOX_SRC_OPERATIONS_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Types.h"

#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox::operations
{
    /**
     * TODO: write docs
     */
    KeyHandlePtr generateKey(const std::string& passphrase);

    /**
     * TODO: write docs
     */
    SignaturePtr signMessage(const MessagePtr& message, const KeyHandlePtr& keyHandle);

    /**
     * TODO: write docs
     */
    bool verifySignature(const SignaturePtr& signature, const MessagePtr& message, const KeyHandlePtr& keyHandle);
}

#endif
