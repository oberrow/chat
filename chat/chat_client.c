#include <stdio.h>
#include <conio.h>
#include <locale.h>
#include "../chat_server/boolean_type.h"
#include <argon2.h>
#include <winsock2.h>
#include <stdlib.h>
#include <Windows.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERROR INVALID_SOCKET
#define HASHLEN 64
#define SALTLEN 32

void Sender();
BOOL MByteToUnicode(LPCSTR  multiByteStr, LPWSTR unicodeStr,    DWORD size);
BOOL UnicodeToMByte(LPCWSTR unicodeStr,   LPSTR  multiByteStr,  DWORD size);
SSL_CTX *create_context();

SOCKET g_Server;
X509                *g_Cert = NULL;
X509_NAME           *g_Certname = NULL;
SSL                 *g_ServerSSL = NULL;
SSL_CTX             *g_Ctx = NULL;
bool g_End = false;
bool g_Authenticated = false;

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
    scanf_s("%s", addr, 128); // Reads ip from user
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
    if(connect(g_Server, (const struct sockaddr*)&serverIp, sizeof serverIp) == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "connect : %d", err);
        return err;
    }
    SSL_set_fd(g_ServerSSL, g_Server);
    SSL_set_verify(g_ServerSSL, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_verify(g_Ctx, SSL_VERIFY_NONE, NULL);
    SSL_set_mode(g_ServerSSL, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_AUTO_RETRY);
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
    const uint32_t t_cost = 2;            // 2-pass computation
    const uint32_t m_cost = (1 << 16);      // 64 mebibytes memory usage
    const uint32_t parallelism = 2;       // number of threads and lanes
    uint16_t salt[SALTLEN];
    srand(time(NULL));
    for (int i = 0; i < SALTLEN; i++)
        salt[i] = rand() * 0x7FF % RAND_MAX;
    // Password/Username getting and writing to file
    char* username =       calloc(128, sizeof(char));
    char* password =       NULL;
    char* hashedPassword = calloc(256, sizeof(char));
    char option1[3] = {0};
    char option2[4] = {0};
    bool opt = false; // true - use saved false enter new ones
    bool opt2 = false; // false log on true sign up
    printf_s("Would you like to sign in or sign up?\nin for signing in or up for signing up (case in-sensitive)\n");
    scanf_s("%s", option1, 3);
    opt2 = ((_stricmp(option1, "up") == 0) && _stricmp(option1, "in") != 0);
    if (!opt2)
    {
        printf("Would you like to use saved credentials or log on using new ones (will overwrite any old ones)\ntype in new for new ones or old for the old ones (case in-sensitive)\n");
        scanf_s("%s", option2, 4);
        opt = ((_stricmp(option2, "old") == 0) && _stricmp(option2, "new") != 0);
        if (!opt)
        {
            password = calloc(256, sizeof(char));
            printf("Enter username!\n");
            scanf_s("%s", username, 128);
            printf("Enter password!\n");
            scanf_s("%s", password, 256);
            ret = argon2id_hash_encoded(t_cost, m_cost, parallelism, password, strlen(password), salt, SALTLEN * 2, HASHLEN, hashedPassword, 256);
            free(password);
            if (ret < 0)
            {
                printf_s("argon2id_hash_encoded failed with exit code : %d\nPress any key to continue...\n", ret);
                (void)_getch();
                SSL_shutdown(g_ServerSSL);
                shutdown(g_Server, SD_BOTH);
                return ret;
            }
        }
        #pragma warning(push)
        #pragma warning(disable : 4996)
            if (opt)
            {
                char ch = '\0';
                FILE* file = fopen("credentials_cli.txt", "r");
                int unameSize, pwdSize;
                for (unameSize = 0; true; unameSize++)
                {
                    ch = getc(file);
                    if (unameSize == 127 || ch == '\n') break;
                    username[unameSize] = ch;
                }
                ch = '\0';
                for (pwdSize = 0; true; pwdSize++)
                {
                    ch = getc(file);
                    if (pwdSize == 255 || ch == -1)
                        break;
                    hashedPassword[pwdSize] = ch;
                }
                fclose(file);
                ret = SSL_write(g_ServerSSL, "CHAT_PROTOCOL_SIGNIN", 20);
                if (ret <= 0)
                {
                    err = SSL_get_error(g_ServerSSL, ret);
                    printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                    if (err == SSL_ERROR_SYSCALL)
                    {
                        err = WSAGetLastError();
                        if (err == 0)
                            perror("err = SSL_ERROR_SYSCALL");
                        else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                        goto alabelinarandomifstamement1;
                    }
                    shutdown(g_Server, SD_BOTH);
                    return err;
                }
                ret = SSL_write(g_ServerSSL, username, unameSize);
                if (ret <= 0)
                {
                    err = SSL_get_error(g_ServerSSL, ret);
                    printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                    if (err == SSL_ERROR_SYSCALL)
                    {
                        err = WSAGetLastError();
                        if (err == 0)
                            perror("err = SSL_ERROR_SYSCALL");
                        else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                        goto alabelinarandomifstamement1;
                    }
                    shutdown(g_Server, SD_BOTH);
                    return err;
                }
                ret = SSL_write(g_ServerSSL, hashedPassword, pwdSize);
                if (ret <= 0)
                {
                    err = SSL_get_error(g_ServerSSL, ret);
                    printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                    if (err == SSL_ERROR_SYSCALL)
                    {
                        err = WSAGetLastError();
                        if (err == 0)
                            perror("err = SSL_ERROR_SYSCALL");
                        else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                        goto alabelinarandomifstamement1;
                    }
                    shutdown(g_Server, SD_BOTH);
                    return err;
                }
                char buf[64];
                ret = SSL_read(g_ServerSSL, buf, 64);
                buf[ret + 1] = 0;
                if (ret <= 0)
                {
                    err = SSL_get_error(g_ServerSSL, ret);
                    printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                    if (err == SSL_ERROR_SYSCALL)
                    {
                        err = WSAGetLastError();
                        if (err == 0)
                            perror("err = SSL_ERROR_SYSCALL");
                        else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                        goto alabelinarandomifstamement1;
                    }
                    alabelinarandomifstamement1:
                    shutdown(g_Server, SD_BOTH);
                    return err;
                }
                if (_stricmp(buf, "CHAT_PROTOCOL_AUTHENTICATED") != 0)
                {
                    printf_s("Error! You were not authenticated to sign in to this account!\nPress any key to continue...");
                    (void)_getch();
                    return ERROR_ACCESS_DENIED;
                }
            }
            else
            {
                FILE* file = fopen("credentials_cli.txt", "w");
                if (file == NULL)
                {
                    perror("Error! Cannot open credentials_cli.txt! Did you delete the file?");
                    printf_s("\nPress any key to continue...");
                    (void)_getch();
                    return ERROR_FILE_NOT_FOUND;
                }
                fprintf_s(file, "%s\n%s", username, hashedPassword);
                fclose(file);
            }
    }
    else
    {
        password = calloc(256, sizeof(char));
        printf("Enter username!\n");
        scanf_s("%s", username, 128);
        printf("Enter password!\n");
        scanf_s("%s", password, 256);
        ret = argon2id_hash_encoded(t_cost, m_cost, parallelism, password, strlen(password), salt, SALTLEN * 2, HASHLEN, hashedPassword, 256);
        free(password);
        ret = SSL_write(g_ServerSSL, "CHAT_PROTOCOL_SIGNUP", 20);
        if (ret <= 0)
        {
            err = SSL_get_error(g_ServerSSL, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = WSAGetLastError();
                if (err == 0)
                    perror("err = SSL_ERROR_SYSCALL");
                else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                goto alabelinarandomifstamement1;
            }
            shutdown(g_Server, SD_BOTH);
            return err;
        }
        ret = SSL_write(g_ServerSSL, username, strlen(username));
        if (ret <= 0)
        {
            err = SSL_get_error(g_ServerSSL, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = WSAGetLastError();
                if (err == 0)
                    perror("err = SSL_ERROR_SYSCALL");
                else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                goto alabelinarandomifstamement1;
            }
            shutdown(g_Server, SD_BOTH);
            return err;
        }
        ret = SSL_write(g_ServerSSL, hashedPassword, strlen(hashedPassword));
        if (ret <= 0)
        {
            err = SSL_get_error(g_ServerSSL, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = WSAGetLastError();
                if (err == 0)
                    perror("err = SSL_ERROR_SYSCALL");
                else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                goto alabelinarandomifstamement1;
            }
            shutdown(g_Server, SD_BOTH);
            return err;
        }
        FILE* file = fopen("credentials_cli.txt", "w");
        if (file == NULL)
        {
            perror("Error! Cannot open credentials_cli.txt! Did you delete the file?");
            printf_s("\nPress any key to continue...");
            (void)_getch();
            return ERROR_FILE_NOT_FOUND;
        }
        fprintf_s(file, "%s\n%s", username, hashedPassword);
        fclose(file);
    }
    free(hashedPassword);
    free(username);
#pragma warning(pop)
    // -----------------------------------------------------------
    auto threadHandle = _beginthread(Sender, 0, NULL);
    setlocale(LC_ALL, "");
    wchar_t ch = L'\0';
    char* buf = calloc(512, 1);
    wchar_t* unicodeBuf = calloc(512 * sizeof(wchar_t), sizeof(wchar_t));
    while (!g_End)
    {
        memset(buf, '\0', 512);
        ret = SSL_read(g_ServerSSL, buf, 512);
        if (ret <= 0)
        {
            err = SSL_get_error(g_ServerSSL, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = GetLastError();
                if (err == 0)
                    perror("\nerr = SSL_ERROR_SYSCALL");
                else printf("\nerr = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
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
    shutdown(g_Server, SD_BOTH);
    free(buf);
    return 0;
}

void Sender()
{
    wchar_t* buf = calloc(512 * sizeof(wchar_t), sizeof(wchar_t));
    char* mbBuf = calloc(512, 1);
    int ret = 0, err = 0;
    DWORD dwBytesRead = 0;
    int index = 0;
    while (!g_End)
    {
        memset(buf, '\0', 512);
        ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), buf, 512 * sizeof(TCHAR), &dwBytesRead, NULL);
        buf[wcslen(buf) - 2] = 0; // Null terminates the CRLF of the inputed string
        UnicodeToMByte(buf, mbBuf, 512);
        ret = SSL_write(g_ServerSSL, mbBuf, strlen(mbBuf));
        if (ret <= 0)
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
                break;
            }
            g_End = true;
            shutdown(g_Server, SD_BOTH);
            break;
        }
    }
    end:
    free(buf);
    free(mbBuf);
    ExitThread(err);
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