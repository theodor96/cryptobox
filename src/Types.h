#ifndef CRYPTOBOX_SRC_TYPES_H
#define CRYPTOBOX_SRC_TYPES_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <memory>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    class KeyHandle;
    class Message;
    class Signature;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    using KeyHandlePtr = std::unique_ptr<KeyHandle>;
    using MessagePtr = std::unique_ptr<Message>;
    using SignaturePtr = std::unique_ptr<Signature>;
}

#endif
