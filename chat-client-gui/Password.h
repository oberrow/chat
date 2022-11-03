#pragma once
#include <keychain.h>

namespace pwd
{
	struct error
	{
		char* errorMsg;
		int ec;
		int size;
	};
	class Password
	{
	public:
		Password();
		Password(const char* package, const char* service);
		Password(const char* package, const char* service, const char* username, const char* password, error* err);
		bool Init(char* username, char* password, error* err);
		bool Init(char* username);
		bool Get(char* pwd, int maxBufSize, error* err);
		void Delete(error* err);

		~Password();
	private:
		const char* m_package = nullptr;
		const char* m_service = nullptr;
		const char* m_username= nullptr;
		keychain::Error m_keyEc;
	};
}