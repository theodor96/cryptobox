#ifndef CRYPTOBOX_SRC_SIGNATURE_H
#define CRYPTOBOX_SRC_SIGNATURE_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Buffer.h"

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    class Signature
    {
    public:
        explicit Signature(Buffer buffer);

        const Buffer& getBuffer() const;

    private:
        Buffer r_buffer;
    };
}

#endif
