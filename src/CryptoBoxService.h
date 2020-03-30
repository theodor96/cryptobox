#include <memory>
#include <string>

namespace cryptobox
{
	class KeyHandleView;
	class Message;
	class Signature;

	class CryptoBoxService
	{
	public:
		using KeyHandleViewPtr = std::unique_ptr<KeyHandleView>;
		using MessagePtr = std::unique_ptr<Message>;
		using SignaturePtr = std::unique_ptr<Signature>;

        CryptoBoxService() = delete;

        /**
         * TODO: write docs
         */
		KeyHandleViewPtr generateKey(const std::string& passPhrase);

        /**
         * TODO: write docs
         */
		SignaturePtr signMessage(const MessagePtr& message, const KeyHandleViewPtr& keyHandleView);

        /**
         * TODO: write docs
         */
		bool verifySignature(const SignaturePtr& signature,
		                     const MessagePtr& message,
		                     const KeyHandleViewPtr& keyHandleView);
	};
}
