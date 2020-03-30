#ifndef SRC_KEYHANDLE_H
#define SRC_KEYHANDLE_H

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

    private:
        std::string r_name;
        std::string r_passphrase;
        Buffer r_publicKey;
    };
}

#endif
