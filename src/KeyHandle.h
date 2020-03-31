#ifndef CRYPTOBOX_SRC_KEYHANDLE_H
#define CRYPTOBOX_SRC_KEYHANDLE_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include "Buffer.h"

#include <string>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    class KeyHandle
    {
    public:
        explicit KeyHandle(Buffer publicKey);

        KeyHandle(std::string name, std::string passphrase);

        const std::string& getName() const;

        const std::string& getPassphrase() const;

        const Buffer& getPublicKey() const;

        void setPublicKey(Buffer publicKey);

        bool hasPublicKey() const;

    private:
        std::string r_name;
        std::string r_passphrase;
        Buffer r_publicKey;
    };
}

#endif
