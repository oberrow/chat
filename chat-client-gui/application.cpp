#include "application.h"
#include <iostream>
#include <thread>
#include <argon2.h>
#include <fstream>
#include <winsock2.h>
#include <sstream>
#include <fstream>
#include <dpapi.h>
#include <keychain.h>
#include <Windows.h>
#include "Password.h"

#line 14 "application.cpp"

#define SERROR INVALID_SOCKET
constexpr const char* package = "com.chat-client.gui";
constexpr const char* service = "usage-client-pwd";

int err = 0;
int ret = 0;
bool connected = false;
SSL* serverSSL = nullptr;
SOCKET serverSocket = INVALID_SOCKET;
Config cnf;
X509* cert = nullptr;
X509_NAME* certname = nullptr;
SSL_CTX* ctx = nullptr;
wxTextCtrl	  * textBox  = nullptr;
wxTextCtrl	  * textBox2 = nullptr;
wxBitmapButton* button1  = nullptr;
bool end = false;

enum class signinopt
{
	oldc,
	newc,
	addnewc
};

bool chat_client_gui_cpp::OnInit()
{
	std::ifstream is{ "Config.txt" };
	cnf.Parse(is);
	is.close();
	WSADATA wsaData;
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err > 0)
	{
		DWORD err = WSAGetLastError();
		fprintf_s(stdout, "Error! WSAStartup was failed with code : %d", err);
		return false;
	}
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	SSL_library_init();
	uint8_t r = 0, g = 0, b = 0; // background colors
	uint8_t fr = 0, fg = 0, fb = 0; // foreground (text) colors
	std::string theme = cnf.map.at("theme");
	if (_stricmp(theme.c_str(), "light") == 0)
	{
		r = 0xFF;
		g = 0xFF;
		b = 0xFF;
	}
	else if (_stricmp(theme.c_str(), "dark") == 0)
	{
		r = 0x36;
		g = 0x39;
		b = 0x3F;
		fr = 0xFF;
		fg = 0xFF;
		fb = 0xFF;
	}
	else
	{
		r = 0x36;
		g = 0x39;
		b = 0x3F;
		fr = 0xFF;
		fg = 0xFF;
		fb = 0xFF;
	}
	frame->SetBackgroundColour(wxColour{ r, g, b });
	frame->Show(true);
	textBox = new wxTextCtrl
	{
		(wxWindow*)frame,
		1,
		wxEmptyString,
		wxDefaultPosition, wxDefaultSize + wxSize(275, 50),
		wxBORDER_NONE | wxTE_RICH | wxTE_MULTILINE,
		wxDefaultValidator, 
		wxTextCtrlNameStr
	};
	textBox->SetBackgroundColour(wxColour{ (wxColourBase::ChannelType)~0x2B, (wxColourBase::ChannelType)~0x22, (wxColourBase::ChannelType)~0xD6 });
	textBox2 = new wxTextCtrl
	{
		(wxWindow*)frame,
		2,
		wxEmptyString,
		wxDefaultPosition + wxPoint(0, 50), wxDefaultSize + wxSize(275, 50),
		wxBORDER_NONE | wxTE_RICH | wxTE_MULTILINE | wxTE_READONLY,
		wxDefaultValidator, 
		wxTextCtrlNameStr
	};
	wxBitmap bmp;
	bmp.LoadFile("#102");
	button1 = new wxBitmapButton
	{
		(wxWindow*)frame,
		BUTTONPRESS,
		bmp,
		wxDefaultPosition + wxPoint(275, 10),
		wxDefaultSize + wxSize(37, 31),
		wxBORDER_RAISED
	};
	button1->SetBackgroundColour(wxColour{ 0x70, 0x7B, 0xF4 });
	button1->SetForegroundColour(wxColour{ (unsigned long)0x000000 });
	textBox->SetBackgroundColour(wxColour{ r, g, b });
	textBox->SetForegroundColour(wxColour{ fr, fg, fb });
	textBox2->SetBackgroundColour(wxColour{ r, g, b });
	textBox2->SetForegroundColour(wxColour{ fr, fg, fb });
	textBoxIn. set_rdbuf(textBox);
	textBoxOut.set_rdbuf(textBox2);
	std::cout .set_rdbuf(textBox2);
	std::cerr .set_rdbuf(textBox2);
	std::cin  .set_rdbuf(textBox);
	std::thread task{ [&]() { InvokeMainLoop(); } };
	task.detach();
	return true;
}

Frame::Frame(const wxString& title, const wxPoint& pos, const wxSize& size)
	: wxFrame(NULL, wxID_ANY, title, pos, size)
{
	wxMenu* menuFile = new wxMenu;
	menuFile->Append(wxID_EXIT);
	wxMenu* menuServer = new wxMenu;
	menuServer->Append(CLOSE_CONN, "Close Connection to server");
	menuServer->Append(CONNECT,	   "Connect to server");
	menuServer->AppendSeparator();
	wxMenu* menuHelp = new wxMenu;
	menuHelp->Append(wxID_ABOUT);
	wxMenuBar* menuBar = new wxMenuBar;
	menuBar->Append(menuFile, "&File");
	menuBar->Append(menuServer, "&Server");
	menuBar->Append(menuHelp, "&Help");
	SetMenuBar(menuBar);
}

void Frame::OnExit(wxCommandEvent& event)
{
	int stat = wxMessageBox(
		"Notice!", "Are you sure you want to exit?",
		wxYES_NO | wxICON_EXCLAMATION
	);
	if (stat == wxYES)
	{
		SSL_shutdown(serverSSL);
		shutdown(serverSocket, SD_BOTH);
		ExitProcess(0);
	}
	else return;
}

void Frame::OnAbout(wxCommandEvent& event)
{
	wxMessageBox("This is a gui client for the chat server",
		"About chat_client_gui", wxOK | wxICON_INFORMATION);
}

void Frame::OnConnect(wxCommandEvent& event)
{
	int ret{}, err{};
	if (connected)
	{
		wxMessageBox("You were already connected to the server.", "Notice!", wxOK | wxICON_EXCLAMATION);
		return;
	}
	int maxSize;
	int size = sizeof(int);
	if (getsockopt(serverSocket, SOL_SOCKET, SO_MAX_MSG_SIZE, (char*)&maxSize, &size) == SOCKET_ERROR)
	{
		serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		serverSSL = SSL_new(ctx);
	}
	std::string ip = cnf.map.at("ip");
	int       port = cnf.map.at("port");
	sockaddr_in serverIp = { 0 };
#pragma warning(push)
#pragma warning(disable : 4996)
	serverIp.sin_addr.s_addr = inet_addr(ip.c_str());
#pragma warning(pop)
	serverIp.sin_family = AF_INET;
	serverIp.sin_port = htons(port);
	if (connect(serverSocket, (const sockaddr*)&serverIp, sizeof serverIp))
	{
		err = WSAGetLastError();
		std::stringstream ss;
		ss << "connect : " << err;
		wxMessageBox(ss.str(), "Error!", wxOK);
		return;
	}
	SSL_set_fd(serverSSL, serverSocket);
	SSL_set_verify(serverSSL, SSL_VERIFY_NONE, NULL);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	SSL_set_mode(serverSSL, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_AUTO_RETRY);
	ret = SSL_connect(serverSSL);
	if (ret <= 0)
	{
		err = SSL_get_error(serverSSL, ret);
		int verifyRes = SSL_get_verify_result(serverSSL);
		std::stringstream ss;
		ss << "Error! SSL_connect has failed with exit code : " << err << " The certificate verify result error is : " << verifyRes << "Line : " << __LINE__ << " File : " __FILE__;
		wxMessageBox(ss.str(), "Error!", wxOK | wxICON_ERROR);
		shutdown(serverSocket, SD_BOTH);
		return;
	}
	connected = true;
	end = false;
	std::thread task{ [&]() { InvokeMainLoop(); } };
	task.detach();
}
void Frame::OnCloseConnect(wxCommandEvent& event)
{
	SSL_write(serverSSL, "CHAT_PROTOCOL_SHUTDOWN", 22);
	SSL_shutdown(serverSSL);
	shutdown(serverSocket, SD_BOTH);
	closesocket(serverSocket);
	connected = false; // to indicate that we have disconnected from the server
}

void Frame::OnPress(wxCommandEvent& event)
{
	::OnPress(event);
	return;
}
void OnPress(wxCommandEvent& event)
{
	int ret{}, err{};
	std::string data = textBox->GetValue().c_str().AsChar(); // all that JUST to get a wxString to a std::string \
	WASTED
	if (data.empty()) return;
	textBox->Clear();
	ret = SSL_write(serverSSL, data.c_str(), data.length());
	if (ret <= 0)
	{
		err = SSL_get_error(serverSSL, ret);
		std::stringstream ss;
		ss << "Error! SSL_write failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
		wxMessageBox(ss.str(), "Error!", wxOK | wxICON_EXCLAMATION);
		if (end) return;
		bool condition = err == 5;
		if (condition)
			err = WSAGetLastError();
		if (condition && err == 0) err = errno;
		if (connected && err != SSL_ERROR_ZERO_RETURN)
			ExitProcess(err);
		else ExitThread(err);
	}
	return;
}

void InvokeMainLoop()
{
	int mainResult = ::ProcMainLoop(__argc, __argv); // calls the main loop
	end = false;
	ExitProcess(mainResult);
}

SSL_CTX* create_context()
{
	const SSL_METHOD* method;
	SSL_CTX* ctx;

	method = TLS_client_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}

int ProcMainLoop(int argc, char** argv)
{
	int maxSize = 0;
	int size = sizeof(int);
	if (getsockopt(serverSocket, SOL_SOCKET, SO_MAX_MSG_SIZE, (char*)&maxSize, &size) == SOCKET_ERROR)
	{
		serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		ctx = create_context();
		serverSSL = SSL_new(ctx);
	}
	if (!connected)
	{
		sockaddr_in serverIp = { 0 };
#pragma warning(push)
#pragma warning(disable : 4996)
		serverIp.sin_addr.s_addr = inet_addr(cnf.map.at("ip").str_Out.c_str());
#pragma warning(pop)
		serverIp.sin_family = AF_INET;
		serverIp.sin_port = htons(cnf.map.at("port").int_Out);
		if (connect(serverSocket, (const sockaddr*)&serverIp, sizeof serverIp) == SERROR)
		{
			connected = false;
			err = WSAGetLastError();
			std::stringstream ss;
			ss << "connect : " << err;
			wxMessageBox(ss.str(), "Error!", wxOK | wxICON_ERROR);
			ExitThread(err);
		}
		connected = true;
		SSL_set_fd(serverSSL, serverSocket);
		SSL_set_verify(serverSSL, SSL_VERIFY_NONE, NULL);
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
		SSL_set_mode(serverSSL, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_AUTO_RETRY);
		ret = SSL_connect(serverSSL);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			int verifyRes = SSL_get_verify_result(serverSSL);
			std::stringstream ss;
			ss << "Error! SSL_connect has failed with exit code : " << err << " The certificate verify result error is : " << verifyRes << "Line : " << __LINE__ << " File : " __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK | wxICON_ERROR);
			shutdown(serverSocket, SD_BOTH);
			ExitThread(err);
		}
	}
	ret = SSL_connect(serverSSL);
	if (ret <= 0)
	{
		err = SSL_get_error(serverSSL, ret);
		int verifyRes = SSL_get_verify_result(serverSSL);
		std::stringstream ss;
		ss << "Error! SSL_connect has failed with exit code : " << err << " The certificate verify result error is : " << verifyRes << " Line : " << __LINE__ << " File : " __FILE__;
		wxMessageBox(ss.str(), "Error!", wxOK | wxICON_ERROR);
		shutdown(serverSocket, SD_BOTH);
		ExitThread(err);
	}
	std::string pingMessage = "@";
	char* username = (char*)calloc(128, sizeof(char));
	char* password = nullptr;
	std::string opt1S;
	bool opt1 = false;
	std::cout << "Would you like to sign in or sign up? enter in for signing in and up for signing up.\n";
	opt1S = ReadTextBox(textBox);
	opt1 = (opt1S == "up") && opt1S != "in";
	textBox->Clear();
	textBox2->Clear();
	char* msg = (char*)calloc(513, sizeof(char));
	if (opt1)
	{
	start:
		textBox->Clear();
		textBox2->Clear();
		std::cout << "Enter your username in the text box!";
		std::string temp = ReadTextBox(textBox).c_str();
		if (temp.length() > 127)
		{
			textBox->Clear();
			textBox2->Clear();
			if (wxMessageBox("Error! your username must be less then 128 characters long! Please try again.", "Error!", wxOK) == wxOK)
				goto start;
		}
		strcpy_s(username, 127, temp.c_str());
		textBox->Clear();
		textBox2->Clear();
		std::cout << "Enter your password!";
		temp = ReadTextBox(textBox);
		password = (char*)calloc(256, 1);
		textBox->Clear();
		if (temp.length() > 255)
		{
			textBox->Clear();
			textBox2->Clear();
			if (wxMessageBox("Error! Your password must be less then 256 characters long! Please try again.", "Error!", wxOK) == wxOK)
				goto start;
		}
		strcpy_s(password, 255, temp.c_str());
		textBox2->Clear();
		SecureZeroMemory((char*)temp.c_str(), temp.length());
		temp.~basic_string();
		pwd::error ec{};
		ec.size = 256;
		ec.errorMsg = (char*)calloc(257, 1);
		pwd::Password pswd{ package, service, username, password, &ec };
		SSL_write(serverSSL, "CHAT_PROTOCOL_SIGNUP", 20);
		SSL_write(serverSSL, username, strlen(username));
		SSL_write(serverSSL, password, strlen(password));
		std::ofstream{ "credentials_cli.txt" } << username;
		SecureZeroMemory(password, 256);
		free(password);
		free(ec.errorMsg);
		ret = SSL_read(serverSSL, msg, 512);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			std::stringstream ss;
			ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK);
			free(msg);
			SSL_shutdown(serverSSL);
			shutdown(serverSocket, SD_BOTH);
			closesocket(serverSocket);
			int lasterr = WSAGetLastError();
			end = true;
			if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
				return err;
			else ExitThread(err);
		}
		if (_stricmp(msg, "CHAT_PROTOCOL_ALREADY_EXISTS") == 0)
		{
			ret = wxMessageBox("Error! The account already exists!", "Error!", wxOK);
			goto start;
		}
	}
	else
	{
		thestartofsignin:
		signinopt nold = signinopt::newc; // old - false new - true
		std::cout << "Would you like to use old credentials, new ones or save new ones (add new)?\n";
 		std::string noldS = ReadTextBox(textBox);
		if (noldS == "old")			 nold = signinopt::oldc;
		else if (noldS == "add new") nold = signinopt::addnewc;
		else if (noldS == "new")	 nold = signinopt::newc;
		else
		{
			int s = wxMessageBox("Error! You didn't enter new old or \"add new\"", "Error!", wxOK);
			textBox->Clear();
			if(s == wxOK) goto thestartofsignin;
		}
		std::string sUname, sPassword;
		pwd::Password pswd{ package, service };
		pwd::error ec{};
		std::string uname;
		switch (nold)
		{
		case signinopt::oldc:
			ec.size = 256;
			ec.errorMsg = (char*)calloc(257, 1);
			std::getline(std::ifstream{ "credentials_cli.txt" }, uname);
			pswd.Init((char*)uname.c_str());
			password = (char*)pswd.Get(&ec);
			if (!password && ec.ec == ERROR_NOT_FOUND)
			{
				int state = wxMessageBox("Error! You don't have any accounts saved in the credentials manager!", "Error!", wxOK);
				if (state == wxOK) return 1;
			}
			SSL_write(serverSSL, "CHAT_PROTOCOL_SIGNIN", 20);
			SSL_write(serverSSL, uname.c_str(), uname.length());
			SSL_write(serverSSL, password, strlen(password));
			SecureZeroMemory(password, strlen(password) + 1);
			free(ec.errorMsg);
			SSL_read(serverSSL, msg, 512);
			if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
			{
				wxMessageBox("Error! You were not authenticated to sign in to this account!", "Error!", wxOK);
				free(msg);
				free(username);
				return 1;
			}
			else if (_stricmp(msg, "CHAT_PROTOCOL_DOESNT_EXIST") == 0)
			{
				wxMessageBox("Error! That account does not exist!", "Error!", wxOK);
				free(msg);
				free(username);
				return 1;
			}
			free(ec.errorMsg);
			break;
		case signinopt::newc:
			textBox->Clear();
			textBox2->Clear();
			std::cout << "Enter your username!";
			sUname = ReadTextBox(textBox);
			textBox->Clear();
			textBox2->Clear();
			std::cout << "Enter your password!";
			sPassword = ReadTextBox(textBox);
			textBox->Clear();
			textBox2->Clear();
			SSL_write(serverSSL, "CHAT_PROTOCOL_SIGNIN", 20);
			SSL_write(serverSSL, sUname.c_str(), sUname.length());
			SSL_write(serverSSL, sPassword.c_str(), sPassword.length());
			SecureZeroMemory((char*)sUname.c_str(), sUname.length());
			SecureZeroMemory((char*)sPassword.c_str(), sPassword.length());
			ret = SSL_read(serverSSL, msg, 512);
			if (ret <= 0)
			{
				err = SSL_get_error(serverSSL, ret);
				std::stringstream ss;
				ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
				wxMessageBox(ss.str(), "Error!", wxOK);
				free(msg);
				SSL_shutdown(serverSSL);
				shutdown(serverSocket, SD_BOTH);
				closesocket(serverSocket);
				int lasterr = WSAGetLastError();
				end = true;
				if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
					return err;
				else ExitThread(err);
			}
			if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
			{
				wxMessageBox("Error! You were not authenticated to sign in to this account!", "Error!", wxOK);
				free(msg);
				free(username);
				return 1;
			}
			else if (_stricmp(msg, "CHAT_PROTOCOL_DOESNT_EXIST") == 0)
			{
				wxMessageBox("Error! That account does not exist!", "Error!", wxOK);
				free(msg);
				free(username);
				return 1;
			}
			goto end;
			break;
		case signinopt::addnewc:
			textBox->Clear();
			textBox2->Clear();
			std::cout << "Enter your username!";
			sUname = ReadTextBox(textBox);
			textBox->Clear();
			textBox2->Clear();
			std::cout << "Enter your password!";
			sPassword = ReadTextBox(textBox);
			textBox->Clear();
			textBox2->Clear();
			ec.size = 256;
			ec.errorMsg = (char*)calloc(257, 1);
			free(ec.errorMsg);
			SSL_write(serverSSL, "CHAT_PROTOCOL_SIGNIN", 20);
			SSL_write(serverSSL, sUname.c_str(), sUname.length());
			SSL_write(serverSSL, sPassword.c_str(), sPassword.length());
			SecureZeroMemory((char*)sUname.c_str(), sUname.length());
			SecureZeroMemory((char*)sPassword.c_str(), sPassword.length());
			ret = SSL_read(serverSSL, msg, 512);
			if (ret <= 0)
			{
				err = SSL_get_error(serverSSL, ret);
				std::stringstream ss;
				ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
				wxMessageBox(ss.str(), "Error!", wxOK);
				free(msg);
				SSL_shutdown(serverSSL);
				shutdown(serverSocket, SD_BOTH);
				closesocket(serverSocket);
				int lasterr = WSAGetLastError();
				end = true;
				if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
					return err;
				else ExitThread(err);
			}
			if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
			{
				wxMessageBox("Error! You were not authenticated to sign in to this account!", "Error!", wxOK);
				free(msg);
				free(username);
				return 1;
			}
			else if (_stricmp(msg, "CHAT_PROTOCOL_DOESNT_EXIST") == 0)
			{
				wxMessageBox("Error! That account does not exist!", "Error!", wxOK);
				free(msg);
				free(username);
				return 1;
			}
			goto end;
			break;
		default:
			break;
		}
	}
		if (_stricmp(msg, "CHAT_PROTOCOL_ALREADY_EXISTS") == 0)
		{
			ret = wxMessageBox("Error! The account already exists!", "Error!", wxOK);
			goto start;
		}
		break;
	}
	case authopt::del:
	{
		std::string uname, pwdS;
		char* pwd = (char*)calloc(256, sizeof(char));
		std::cout << "Enter your username!\n";
		uname = ReadTextBox(textBox);
		textBox->Clear();
		textBox2->Clear();
		std::cout << "Enter your password!\n";
		pwdS = ReadTextBox(textBox);
		textBox->Clear();
		textBox2->Clear();
		strcpy_s(pwd, 256, pwdS.c_str());
		SecureZeroMemory((void*)pwdS.c_str(), pwdS.length());
		pwdS.~basic_string();
		SSL_write(serverSSL, "CHAT_PROTOCOL_SIGNIN", 20);
		SSL_write(serverSSL, uname.c_str(), uname.length());
		SSL_write(serverSSL, pwd, strlen(pwd));
		SecureZeroMemory((char*)uname.c_str(), uname.length());
		ret = SSL_read(serverSSL, msg, 512);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			std::stringstream ss;
			ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK);
			free(msg);
			SSL_shutdown(serverSSL);
			shutdown(serverSocket, SD_BOTH);
			closesocket(serverSocket);
			int lasterr = WSAGetLastError();
			end = true;
			if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
				return err;
			else ExitThread(err);
		}
		if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
		{
			wxMessageBox("Error! You were not authenticated to sign in to this account!", "Error!", wxOK);
			free(msg);
			free(pwd);
			free(username);
			return 1;
		}
		else if (_stricmp(msg, "CHAT_PROTOCOL_DOESNT_EXIST") == 0)
		{
			wxMessageBox("Error! That account does not exist!", "Error!", wxOK);
			free(msg);
			free(pwd);
			free(username);
			return 1;
		}
		SSL_write(serverSSL, "CHAT_PROTOCOL_REMOVE", 20);
		SSL_write(serverSSL, pwd, strlen(pwd));
		ret = SSL_read(serverSSL, msg, 512);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			std::stringstream ss;
			ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK);
			free(msg);
			SSL_shutdown(serverSSL);
			shutdown(serverSocket, SD_BOTH);
			closesocket(serverSocket);
			int lasterr = WSAGetLastError();
			end = true;
			if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
				return err;
			else ExitThread(err);
		}
		if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
		{
			wxMessageBox("Error! You were not authenticated to delete this account!", "Error!", wxOK);
			free(msg);
			free(username);
			return 1;
		}
		else
		{
			return 0;
		}
		SecureZeroMemory(pwd, strlen(pwd));
		free(pwd);
		goto end;
		break;
	}
	case authopt::change:
	{
		std::string uname, pwdS, newPwdS;
		char* pwd = (char*)calloc(256, sizeof(char));
		char* newPwd = (char*)calloc(256, sizeof(char));
		std::cout << "Enter your username!\n";
		uname = ReadTextBox(textBox);
		textBox->Clear();
		textBox2->Clear();
		std::cout << "Enter your password!\n";
		pwdS = ReadTextBox(textBox);
		textBox->Clear();
		textBox2->Clear();
		std::cout << "Enter the new password!\n";
		newPwdS = ReadTextBox(textBox);
		textBox->Clear();
		textBox2->Clear();
		strcpy_s(pwd, 256, pwdS.c_str());
		SecureZeroMemory((void*)pwdS.c_str(), pwdS.length());
		pwdS.~basic_string();
		strcpy_s(newPwd, 256, newPwdS.c_str());
		SecureZeroMemory((void*)newPwdS.c_str(), newPwdS.length());
		newPwdS.~basic_string();
		SSL_write(serverSSL, "CHAT_PROTOCOL_SIGNIN", 20);
		SSL_write(serverSSL, uname.c_str(), uname.length());
		SSL_write(serverSSL, pwd, strlen(pwd));
		SecureZeroMemory((char*)uname.c_str(), uname.length());
		ret = SSL_read(serverSSL, msg, 512);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			std::stringstream ss;
			ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK);
			free(msg);
			SSL_shutdown(serverSSL);
			shutdown(serverSocket, SD_BOTH);
			closesocket(serverSocket);
			int lasterr = WSAGetLastError();
			end = true;
			if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
				return err;
			else ExitThread(err);
		}
		if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
		{
			wxMessageBox("Error! You were not authenticated to sign in to this account!", "Error!", wxOK);
			free(msg);
			free(username);
			return 1;
		}
		else if (_stricmp(msg, "CHAT_PROTOCOL_DOESNT_EXIST") == 0)
		{
			wxMessageBox("Error! That account does not exist!", "Error!", wxOK);
			free(msg);
			free(username);
			return 1;
		}
		SSL_write(serverSSL, "CHAT_PROTOCOL_CHANGE_PWD", 25);
		SSL_write(serverSSL, pwd, strlen(pwd));
		SSL_write(serverSSL, newPwd, strlen(newPwd));
		ret = SSL_read(serverSSL, msg, 512);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			std::stringstream ss;
			ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK);
			free(msg);
			SSL_shutdown(serverSSL);
			shutdown(serverSocket, SD_BOTH);
			closesocket(serverSocket);
			int lasterr = WSAGetLastError();
			end = true;
			if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
				return err;
			else ExitThread(err);
		}
		if (_stricmp(msg, "CHAT_PROTOCOL_INVALID_PASSWORD") == 0)
		{
			wxMessageBox("Error! You were not authenticated to sign in to this account!", "Error!", wxOK);
			free(msg);
			free(username);
			return 1;
		}
		break;
	}
	default:
		break;
	}
	end:
	pingMessage.append(username);
	free(username);
	std::thread task{ [&]() 
		{
			int ret2{}, err2{};
			std::string str = "";
			while (true && !end)
			{
				str = ReadTextBox(textBox);
				if (str.length() >= 512)
				{
					wxMessageBox("Wow! That's a big message you sent there! Maximum message size is 512.", "Whoa!", wxOK | wxICON_EXCLAMATION);
					str = "";
					textBox->Clear();
					continue;
				}
				if (str == "/whoami") str = "CHAT_PROTOCOL_WHOAMI";
				else if (str == "/list") str = "CHAT_PROTOCOL_LISTONLINEUSERS";
				if(!str.empty())
					ret2 = SSL_write(serverSSL, str.c_str(), str.length());
				if (ret2 <= 0)
				{
					err2 = SSL_get_error(serverSSL, ret2);
					std::stringstream ss;
					ss << "Error! SSL_write failed with exit code : " << err2 << "! Line : " << __LINE__ << " File : " << __FILE__;
					wxMessageBox(ss.str(), "Error!", wxOK | wxICON_EXCLAMATION);
					if (end) break;
					free(msg);
					bool condition = err2 == 5;
					if (condition)
						err2 = WSAGetLastError();
					if (condition && err2 == 0) err2 = errno;
					if (connected && err != SSL_ERROR_ZERO_RETURN)
						ExitProcess(err2);
					else ExitThread(err2);
				}
				textBox->Clear();
			}
		} };
	task.detach();
	while(1)
	{
		memset(msg, 0, 512);
		ret = SSL_read(serverSSL, msg, 512);
		if (ret <= 0)
		{
			err = SSL_get_error(serverSSL, ret);
			std::stringstream ss;
			ss << "Error! SSL_read failed with exit code : " << err << "! Line : " << __LINE__ << " File : " << __FILE__;
			wxMessageBox(ss.str(), "Error!", wxOK);
			free(msg);
			SSL_shutdown(serverSSL);
			shutdown    (serverSocket, SD_BOTH);
			closesocket (serverSocket);
			int lasterr = WSAGetLastError();
			end = true;
			if (connected && err != SSL_ERROR_ZERO_RETURN) // if you didn't disconnect and the server didn't disconnect
				return err;
			else ExitThread(err);
		}
		std::cout << msg << '\n';
		std::string msgStr = msg;
		if (msgStr.find('[') != std::string::npos) msgStr.erase(0, msgStr.length() - msgStr.find(']') - 1);
		if (msgStr == pingMessage)
		{
			Beep(350, 81);
			Beep(360, 81);
			Beep(365, 81);
			Beep(370, 81);
			Beep(500, 81);
			Beep(1000, 81);
		}
	}
	free(msg);
	return 0;
}

std::string ReadTextBox(wxTextCtrl* textbox, char delim)
{
	textbox->Enable();
	std::string temp;
	int val = 0;
	while (temp.find(delim) == std::string::npos)
	{
		if (end) break;
		temp = textbox->GetValue();
		val = temp.length() + 1;
	}
	if(!temp.empty()) temp.pop_back();
	return temp;
}
