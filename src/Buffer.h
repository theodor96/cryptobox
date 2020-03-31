#ifndef CRYPTOBOX_SRC_BUFFER_H
#define CRYPTOBOX_SRC_BUFFER_H

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

#include <cstddef>
#include <string>
#include <vector>

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// fwd decl

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

namespace cryptobox
{
    class Buffer
    {
    public:
        using InternalBuffer = std::vector<unsigned char>;

        Buffer() = default;

        explicit Buffer(std::size_t size);

        static Buffer createFromText(const std::string& text);

        static Buffer createFromHex(const std::string& hex);

        static Buffer createFromRawBuffer(const unsigned char* rawBuffer, std::size_t rawBufferSize);

        static Buffer createFromInternalBuffer(const InternalBuffer& buffer);

        std::string toHex() const;

        unsigned char* getWriteableRawBuffer();

        const unsigned char* getRawBuffer() const;

        std::size_t getSize() const;

        bool isEmpty() const;

        void append(const Buffer& buffer);

        const InternalBuffer& getInternalBuffer() const;

    private:
        InternalBuffer r_buffer;

        explicit Buffer(InternalBuffer r_buffer);
    };
}

#endif
