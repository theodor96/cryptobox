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
    Buffer::Buffer(std::size_t size)
    : r_buffer(size)
    {

    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

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

    Buffer Buffer::createFromRawBuffer(const unsigned char* rawBuffer, std::size_t rawBufferSize)
    {
        return Buffer{InternalBuffer{rawBuffer, rawBuffer + rawBufferSize}};
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

    unsigned char* Buffer::getWriteableRawBuffer()
    {
        return r_buffer.data();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    const unsigned char* Buffer::getRawBuffer() const
    {
        return r_buffer.data();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    std::size_t Buffer::getSize() const
    {
        return r_buffer.size();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    bool Buffer::isEmpty() const
    {
        return r_buffer.empty();
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    void Buffer::append(const Buffer& rhs)
    {
        r_buffer.insert(r_buffer.end(), rhs.r_buffer.cbegin(), rhs.r_buffer.cend());
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    Buffer::Buffer(InternalBuffer buffer)
    : r_buffer{std::move(buffer)}
    {

    }
}
