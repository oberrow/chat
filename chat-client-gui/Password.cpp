#include "password.h"

namespace pwd
{
	Password::Password() 
	{}
	Password::Password(const char* package, const char* service)
		:m_package{ package }, m_service{ service }
	{}
	Password::Password(const char* package, const char* service, const char* username, const char* password, error* err)
		:m_package{ package }, m_service{ service }, m_username{ username }
	{
		err->ec = 0;
		keychain::setPassword(m_package, m_service, m_username, password, m_keyEc);
		if (m_keyEc)
		{
			strcpy_s(err->errorMsg, err->size, m_keyEc.message.c_str());
			err->ec = m_keyEc.code;
			return;
		}
	}
	bool Password::Init(char* username, char* password, error* err)
	{
		if (err->size == 0) return false;
		m_username = username;
		keychain::setPassword(m_package, m_service, m_username, password, m_keyEc);
		if (m_keyEc)
		{
			strcpy_s(err->errorMsg, err->size, m_keyEc.message.c_str());
			err->ec = m_keyEc.code;
			return false;
		}
		return true;
	}
	bool Password::Init(char* username)
	{
		m_username = username;
		return true;
	}
	const char* Password::Get(error* err)
	{
		if (err->size == 0) return nullptr;
		auto password = keychain::getPassword(m_package, m_service, m_username, m_keyEc);
		if (m_keyEc)
		{
			strcpy_s(err->errorMsg, err->size, m_keyEc.message.c_str());
			err->ec = m_keyEc.code;
			return nullptr;
		}
		keychain::setPassword(m_package, m_service, m_username, password, m_keyEc);
		if (m_keyEc)
		{
			strcpy_s(err->errorMsg, err->size, m_keyEc.message.c_str());
			err->ec = m_keyEc.code;
			return nullptr;
		}
		return password.c_str();
	}
	void Password::Delete(error* err)
	{
		keychain::deletePassword(m_package, m_service, m_username, m_keyEc);
		if (m_keyEc)
		{
			err->ec = m_keyEc.code;
			strcpy_s(err->errorMsg, err->size, m_keyEc.message.c_str());
		}
	}
	Password::~Password() 
	{
	}
}