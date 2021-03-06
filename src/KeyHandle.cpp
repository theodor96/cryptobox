#include "KeyHandle.h"

#include <utility>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    KeyHandle::KeyHandle(Buffer publicKey)
    : r_name{},
      r_passphrase{},
      r_publicKey{std::move(publicKey)}
    {

    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    KeyHandle::KeyHandle(std::string name, std::string passphrase)
    : r_name{std::move(name)},
      r_passphrase{std::move(passphrase)},
      r_publicKey{}
    {

    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    const std::string& KeyHandle::getName() const
    {
        return r_name;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    const std::string& KeyHandle::getPassphrase() const
    {
        return r_passphrase;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    const Buffer& KeyHandle::getPublicKey() const
    {
        return r_publicKey;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    void KeyHandle::setPublicKey(Buffer publicKey)
    {
        r_publicKey = std::move(publicKey);
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool KeyHandle::hasPublicKey() const
    {
        return !r_publicKey.isEmpty();
    }
}
