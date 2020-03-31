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
        Buffer() = default;

        explicit Buffer(std::size_t size);

        /**
         * TODO: docs
         */
        static Buffer createFromText(const std::string& text);

        /**
         * TODO: docs
         */
        static Buffer createFromHex(const std::string& hex);

        /**
         * TODO: docs
         */
        static Buffer createFromRawBuffer(const unsigned char* rawBuffer, std::size_t rawBufferSize);

        /**
         * TODO: docs
         */
        std::string toHex() const;

        /**
         * TODO: docs
         */
        unsigned char* getWriteableRawBuffer();

        /**
         * TODO: docs
         */
        const unsigned char* getRawBuffer() const;

        /**
         * TODO: docs
         */
        std::size_t getSize() const;

        /**
         * TODO: docs
         */
        bool isEmpty() const;

        /**
         * TODO: docs
         */
        void append(const Buffer& buffer);

    private:
        using InternalBuffer = std::vector<unsigned char>;

        InternalBuffer r_buffer;

        explicit Buffer(InternalBuffer r_buffer);
    };
}

#endif
