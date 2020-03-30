#include "Buffer.h"

#include "detail/HexIterator.h"

#include <algorithm>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <stdexcept>
#include <utility>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    Buffer Buffer::createFromText(const std::string& text)
    {
        return createFromRawBuffer(reinterpret_cast<const unsigned char*>(text.c_str()), text.size());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Buffer Buffer::createFromHex(const std::string& hex)
    {
        if (hex.length() % 2)
        {
            throw std::invalid_argument{"Invalid hex number " + hex};
        }

        InternalBuffer buffer{};
        buffer.reserve(hex.length() / 2);
        std::copy(hex.cbegin(), hex.cend(), detail::getHexIterator(std::back_inserter(buffer)));

        return buffer;
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Buffer Buffer::createFromRawBuffer(const unsigned char* rawBuffer, std::size_t rawBufferLength)
    {
        return Buffer{InternalBuffer{rawBuffer, rawBuffer + rawBufferLength}};
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    std::string Buffer::toHex() const
    {
        std::stringstream hexStream{};

        hexStream << std::hex;
        for (const auto& byte : r_buffer)
        {
            hexStream << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
        }

        return hexStream.str();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Buffer::Buffer(InternalBuffer buffer)
    : r_buffer{std::move(buffer)}
    {

    }
}
