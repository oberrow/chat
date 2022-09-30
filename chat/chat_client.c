#include <stdio.h>
#include <conio.h>
#include <locale.h>
#include <stdbool.h>
#include <winsock2.h>
#include <Windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERROR INVALID_SOCKET


void Receiver();
BOOL MByteToUnicode(LPCSTR  multiByteStr, LPWSTR unicodeStr,    DWORD size);
BOOL UnicodeToMByte(LPCWSTR unicodeStr,   LPSTR  multiByteStr,  DWORD size);
SSL_CTX *create_context();
static int always_true_callback(X509_STORE_CTX* ctx, void* arg)
{
    return 1;
}

SOCKET g_Server;
X509                *g_Cert = NULL;
X509_NAME           *g_Certname = NULL;
SSL                 *g_ServerSSL = NULL;
SSL_CTX             *g_Ctx = NULL;
bool g_End = false;

int main(int argc, char **argv, char **envp)
{
    SSL_load_error_strings();
    ERR_load_crypto_strings();
    int ret = 0, err = 0;
    if(SSL_library_init() < 0)
    {
        err = SSL_get_error(g_ServerSSL, ret);
        printf("SSL_library_init failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d", err, __LINE__);
        g_End = true;
        shutdown(g_Server, SD_BOTH);
        return err;
    }
    WSADATA wsaData;
    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if(err != 0)
    {
        fprintf(stderr, "WSAStartup : %d", err);
        return err;
    }
    g_Ctx = create_context();
    SSL_CTX_set_options(g_Ctx, SSL_OP_NO_SSLv2);
    g_ServerSSL = SSL_new(g_Ctx);
    g_Server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(g_Server == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "socket : %d", err);
        return err;
    }
    char* addr = calloc(128, 1);
    int port = 0;
    printf("Enter server ip : \n");
    scanf_s("%s", addr, 127); // Reads ip from user
    printf("Enter server port : \n");
    scanf_s("%d", &port); // Reads ip from user
    struct sockaddr_in serverIp = {0};
#pragma warning(push)
#pragma warning(disable : 4996)
    serverIp.sin_addr.s_addr = inet_addr(addr);
#pragma warning(pop)
    serverIp.sin_family = AF_INET;
    serverIp.sin_port = htons(port);
    free(addr);
    //SSL_CTX_set_cert_verify_callback(g_Ctx, always_true_callback, NULL);
    if(connect(g_Server, (const struct sockaddr*)&serverIp, sizeof serverIp) == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "connect : %d", err);
        return err;
    }
    SSL_set_fd(g_ServerSSL, g_Server);
    SSL_set_verify(g_ServerSSL, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(g_Ctx, SSL_VERIFY_NONE, NULL);
    SSL_set_mode(g_ServerSSL, SSL_MODE_ASYNC);
    ret = SSL_connect(g_ServerSSL);
    if (ret <= 0)
    {
        err = SSL_get_error(g_ServerSSL, ret);
        int verifyRes = SSL_get_verify_result(g_ServerSSL);
        printf("SSL_connect failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Certificate verification result : %d, Line : %d", err, verifyRes, __LINE__);
        g_End = true;
        shutdown(g_Server, SD_BOTH);
        return err;
    }
    wchar_t* buf = calloc(512 * sizeof(wchar_t), sizeof(wchar_t));
    char* mbBuf = calloc(512, 1);
    auto threadHandle = _beginthread(Receiver, 0, NULL);
    DWORD dwBytesRead = 0;
    setlocale(LC_ALL, "");
    wchar_t ch = L'\0';
    int index = 0;
    while(!g_End)
    {
        memset(buf, '\0', 512);
        ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buf, 512 * sizeof(TCHAR), &dwBytesRead, NULL);
        buf[wcslen(buf) - 2] = 0; // Null terminates the CRLF of the inputed string
        UnicodeToMByte(buf, mbBuf, 512);
        ret = SSL_write(g_ServerSSL, mbBuf, wcslen(mbBuf));
        if(ret <= 0)
        {
            err = SSL_get_error(g_ServerSSL, err);
            printf("SSL_write failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = WSAGetLastError();
                if (err == 0)
                    perror("err = SSL_ERROR_SYSCALL");
               else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                g_End = true;
                return err;
            }
            g_End = true;
            shutdown(g_Server, SD_BOTH);
            return err;
        }
    }
    shutdown(g_Server, SD_BOTH);
    free(buf);
    free(mbBuf);
    return 0;
}

void Receiver()
{
    int err = 0, ret = 0;
    char* buf = calloc(512, 1);
    wchar_t* unicodeBuf = calloc(512 * sizeof(wchar_t), sizeof(wchar_t));
    while(!g_End)
    {
        memset(buf, '\0', 512);
        ret = SSL_read(g_ServerSSL, buf, strlen(buf));
        if(ret <= 0)
        {
            err = SSL_get_error(g_ServerSSL, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = WSAGetLastError();
                if (err == 0)
                    perror("err = SSL_ERROR_SYSCALL");
                else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                g_End = true;
                ExitThread(-1);
            }
            g_End = true;
            shutdown(g_Server, SD_BOTH);
            ExitThread(err);
        }
        MByteToUnicode(buf, unicodeBuf, 512);
        wprintf(L"%ls \n", unicodeBuf);
    }
    _endthread();
}
// Next 2 functions : https://social.msdn.microsoft.com/Forums/vstudio/en-US/41f3fa1c-d7cd-4ba6-a3bf-a36f16641e37/conversion-from-multibyte-to-unicode-character-set
BOOL MByteToUnicode(LPCSTR multiByteStr, LPWSTR unicodeStr, DWORD size)
{
    // Get the required size of the buffer that receives the Unicode string. 
    DWORD minSize;
    minSize = MultiByteToWideChar (CP_ACP, 0, multiByteStr, -1, NULL, 0);
    
    if(size < minSize)
    {
     return FALSE;
    } 
    
    // Convert string from multi-byte to Unicode.
    MultiByteToWideChar (CP_ACP, 0, multiByteStr, -1, unicodeStr, minSize); 
    return TRUE;
}

BOOL UnicodeToMByte(LPCWSTR unicodeStr, LPSTR multiByteStr, DWORD size)
{
    // Get the required size of the buffer that receives the multiByte string. 
    DWORD minSize;
    minSize = WideCharToMultiByte(CP_OEMCP,NULL,unicodeStr,-1,NULL,0,NULL,FALSE);
    if(size < minSize)
    {
    	return FALSE;
    }
    // Convert string from Unicode to multi-byte.
    WideCharToMultiByte(CP_OEMCP,NULL,unicodeStr,-1,multiByteStr,size,NULL,FALSE);
    return TRUE;
}
SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    
    method = TLS_client_method();
    
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    
    return ctx;
}