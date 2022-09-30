#include <stdio.h>
#include <conio.h>
#include <winsock2.h>
#include <stdbool.h>
#include <openssl\ssl.h>
#include <openssl\err.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERROR INVALID_SOCKET
#define INITALIZE_SSL_VECTOR(x)     x.sslList = calloc(sizeof(SSL*), sizeof(SSL*)); x.sslListSize = 0

struct socket_vector
{
    SOCKET* socketList;
    int socketListSize;
};
struct ssl_vector
{
    SSL **sslList;
    int   sslListSize;
};
SOCKET               g_ServerSocket;
SOCKET               g_ClientSocket;
SSL*                 g_Con_SSL = NULL;
struct sockaddr      g_ClientAddress;
struct socket_vector g_Clients;
struct ssl_vector    g_Clients_SSL;
SSL_CTX*             g_Ctx;


void ClientHandler();
BOOL MByteToUnicode(LPCSTR  multiByteStr, LPWSTR unicodeStr,    DWORD size);
BOOL UnicodeToMByte(LPCWSTR unicodeStr,   LPSTR  multiByteStr,  DWORD size);
// Next 2 functions taken from https://wiki.openssl.org/index.php/Simple_TLS_Server
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx);

int main(int argc, char **argv, char **envp)
{
    if(SSL_library_init() < 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    g_Clients.socketList = calloc(sizeof(SOCKET), sizeof(SOCKET));
    g_Clients.socketListSize = 0;
    INITALIZE_SSL_VECTOR(g_Clients_SSL);
    g_Ctx = create_context();
    configure_context(g_Ctx);
    int err = 0;
    WSADATA wsaData;
    err = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if(err != 0)
    {
        fprintf(stderr, "WSAStartup : %d", err);
        return err;
    }
    struct sockaddr_in saServer;
    // Set up the sockaddr structure
    saServer.sin_family = AF_INET;
#pragma warning(push)
#pragma warning(disable : 4996)
    saServer.sin_addr.s_addr = inet_addr("127.0.0.1");
#pragma warning(pop)
    saServer.sin_port = htons(443);
    g_ServerSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(g_ServerSocket == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "socket : %d", err);
        return err;
    }
    if(bind(g_ServerSocket, (struct sockaddr*)&saServer, sizeof saServer) == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "bind : %d", err);
        return err;
    }

    printf("Listening on port 443!\n");
    
    if(listen(g_ServerSocket, SOMAXCONN) == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "listen : %d", err);
        return err;
    }
    int i = 0;
    int cAddrLen = sizeof g_ClientAddress;
    while(true)
    {
        g_ClientSocket = accept(g_ServerSocket, &g_ClientAddress, &cAddrLen);
        auto threadHandle = _beginthread(ClientHandler, 0, NULL);
        g_Con_SSL = SSL_new(g_Ctx);
        SSL_set_fd(g_Con_SSL, g_ClientSocket);
        if(g_ClientSocket == SERROR)
        {
            err = WSAGetLastError();
            fprintf(stderr, "accept : %d", err);
            return err;
        }
        if(g_Clients.socketListSize == 0)
        {
            g_Clients.socketList[i] = g_ClientSocket;
            g_Clients.socketListSize++;
            g_Clients_SSL.sslList[i] = g_Con_SSL;
            g_Clients_SSL.sslListSize++;
            i++;
        }
        else
        {
            void* preBuf = _recalloc(g_Clients.socketList, g_Clients.socketListSize + 1, sizeof(SOCKET));
            if(preBuf == NULL)
            {
                perror("_recalloc : ");
                return -1;
            }
            g_Clients.socketList = preBuf;
            g_Clients.socketList[i] = g_ClientSocket;
            g_Clients.socketListSize++;
            void* preBuf2 = _recalloc(g_Clients_SSL.sslList, g_Clients_SSL.sslListSize + 1, sizeof(SSL*));
            if(preBuf2 == NULL)
            {
                perror("_recalloc : ");
                return -1;
            }
            g_Clients_SSL.sslList = preBuf;
            g_Clients_SSL.sslList[i] = g_Con_SSL;
            g_Clients_SSL.sslListSize++;
            i++;
        }
    }
    SSL_CTX_free(g_Ctx);
    return 0;
}

void ClientHandler()
{
    // gets the current client's socket handle / ssl connection hopefully before a new client connects
    SOCKET thisClient =  g_ClientSocket;
    SSL* ssl          =  g_Con_SSL;
    char* buf = calloc(512, 1);
    int ret = 0, err = 0;
    puts("Client connected!");
    ret = SSL_accept(ssl);
    if (ret <= 0) 
    {
        err = SSL_get_error(ssl, ret);
        printf("SSL_accept failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
        shutdown(thisClient, SD_BOTH);
        free(buf);
        goto end;
    }
    puts("SSL initalized!");
    while(true)
    {
        memset(buf, '\0', 512);
        if(SSL_read(ssl, buf, 512) <= 0)
        {
            err = SSL_get_error(ssl, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
            shutdown(thisClient, SD_BOTH);
            free(buf);
            break;
        }
        for(int i = 0; i < g_Clients_SSL.sslListSize; i++)
        {
            if(SSL_write(g_Clients_SSL.sslList[i], buf, strlen(buf)) <= 0)
            {
                continue;
            }
        }
    }
    end:
    puts("Closed connection to client!");
    free(buf);
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

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}
void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}