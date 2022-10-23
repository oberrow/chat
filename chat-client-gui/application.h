#pragma once
#define WIN32_LEAN_AND_MEAN
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include "config.hpp"
#pragma warning(push)
#pragma warning(disable : 4996)
#include <wx/wx.h>
#pragma warning(pop)

extern int err;
extern int ret;
extern bool connected;
extern SSL* serverSSL;
extern SOCKET serverSocket;
extern Config cnf;
extern X509* cert;
extern X509_NAME* certname;
extern SSL_CTX* ctx;
extern wxTextCtrl	 * textBox;
extern wxTextCtrl	 * textBox2;
extern wxBitmapButton* button1;
extern bool end;

enum
{
	CLOSE_CONN = 1,
	CONNECT,
	BUTTONPRESS
};

void OnPress(wxCommandEvent& event);
int  ProcMainLoop(int argc, char** argv);
void InvokeMainLoop();
SSL_CTX* create_context();
std::string ReadTextBox(wxTextCtrl* textbox, char delim = '\n');

class Frame : public wxFrame
{
public:
	Frame(const wxString& title, const wxPoint& pos, const wxSize& size);
private:
	wxDECLARE_EVENT_TABLE();
	void OnExit(wxCommandEvent& event);
	void OnAbout(wxCommandEvent& event);
	void OnConnect(wxCommandEvent& event);
	void OnCloseConnect(wxCommandEvent& event);
	void OnPress(wxCommandEvent& event);
};

#if !defined(NO_EVENT_DEFINE)
wxBEGIN_EVENT_TABLE(Frame, wxFrame)
EVT_MENU  (wxID_EXIT  , Frame::OnExit)
EVT_MENU  (wxID_ABOUT , Frame::OnAbout)
EVT_MENU  (CLOSE_CONN , Frame::OnCloseConnect)
EVT_MENU  (CONNECT    , Frame::OnConnect)
EVT_BUTTON(BUTTONPRESS, Frame::OnPress)
wxEND_EVENT_TABLE()
#endif

class chat_client_gui_cpp : public wxApp
{
public:
    virtual bool OnInit();
	std::ostream textBoxOut{ std::_Uninitialized(), true };
	std::istream textBoxIn { std::_Uninitialized()       };
	Frame* frame = new Frame("chat_client_gui", wxPoint(50, 50), wxSize(400, 300));
};