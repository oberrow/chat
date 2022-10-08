#include <stdio.h>
#include <conio.h>
#include "boolean_type.h"
#include <vec.h>
#include <uthash.h>
#include <winsock2.h>
#include <openssl\ssl.h>
#include <openssl\err.h>

#pragma comment(lib, "Ws2_32.lib")

#define SERROR INVALID_SOCKET

#pragma warning(disable : 6387)

typedef struct _password_map
{
    char* username;
    char* password;
    UT_hash_handle hh;
} password_map, *p_password_map;
SOCKET               g_ServerSocket;
SOCKET               g_ClientSocket;
SSL*                 g_Con_SSL = NULL;
struct sockaddr      g_ClientAddress;
SOCKET*        g_Clients;
SSL**          g_Clients_SSL;
p_password_map g_ClientPasswords = NULL;
SSL_CTX* g_Ctx;
uint64_t g_ClientCount = 0;

void ClientHandler();
void EchoMessage(const void* buffer, int sizeInBytes);
bool AppendToString(char ch, char** buffer, size_t size);
char* getline(FILE* stream, int* len);
void AddToMap(char* key, char* hash);
void MapGet  (char* key, char* data, size_t bufsize);
bool ParameterHandler(enum paramflags* flag, int element, char** str1, int* int1);
BOOL MByteToUnicode(LPCSTR  multiByteStr, LPWSTR unicodeStr,    DWORD size);
BOOL UnicodeToMByte(LPCWSTR unicodeStr,   LPSTR  multiByteStr,  DWORD size);
void GetClientIdsFromFile(FILE* stream);
// Next 2 functions taken from https://wiki.openssl.org/index.php/Simple_TLS_Server
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, char* keyfname, char* certname);
// https://learn.microsoft.com/en-us/windows/console/handlerroutine
BOOL WINAPI HandlerRoutine(
    _In_ DWORD dwCtrlType
);

enum paramflags
{
    DEFAULT, // default flag
    READ, // Start reading from the next argument
    FPORT, // --port was specified
    FIP, // --ip was specified
    FCERTFNAME, // --certificate_fname certificate file path
    FPRIVATEKEYFNAME, // --privatekey_fname
    FHELP, // --help, -h
    INVALID // an invalid option was specified
};

int main(int argc, char **argv, char **envp)
{
    FILE* file = fopen("credentials.txt", "r");
    GetClientIdsFromFile(file);
    fclose(file);
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
    g_Clients = vector_create();
    g_Clients_SSL = vector_create();
    enum paramflags par = DEFAULT;
    int port = 443;
    char* ip = "127.0.0.1";
    char* certname = "cert.pem";
    char* privkeyname = "key.pem";
    char** funcpar = NULL;
    for (int i = 1; i < argc; i++)
    {
        if (par == READ) 
          { par = DEFAULT; continue; }
        char* element = argv[i];
        if (_stricmp(element, "--port") == 0)
        {
            par = FPORT;
            ParameterHandler(&par, i, NULL, &port);
        }
        else if (_stricmp(element, "--ip") == 0)
        {
            par = FIP;
            ParameterHandler(&par, i, &ip, NULL);
        }
        else if (_stricmp(element, "--certificate_fname") == 0)
        {
            par = FCERTFNAME;
            ParameterHandler(&par, i, &certname, NULL);
        }
        else if (_stricmp(element, "--privatekey_fname") == 0) 
        {
            par = FPRIVATEKEYFNAME;
            ParameterHandler(&par, i, &privkeyname, NULL);
        }
        else if (_stricmp(element, "--help") == 0 || _stricmp(element, "-h") == 0)
        { 
            par = FHELP;
            ParameterHandler(&par, i, NULL, NULL);
            return 0;
        }
        else
        {
            printf("You entered an invalid parameter! Parameter was : %s\n", element);
            par = INVALID;
            ParameterHandler(&par, i, NULL, NULL);
            return 1;
        }
    }
    if(SSL_library_init() < 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    g_Ctx = create_context();
    configure_context(g_Ctx, privkeyname, certname);
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
    saServer.sin_addr.s_addr = inet_addr(ip);
#pragma warning(pop)
    saServer.sin_port = htons(port);
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
    printf("Listening on port %d!\n", port);
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
        g_ClientCount++;
        auto threadHandle = _beginthread(ClientHandler, 0, NULL);
        g_Con_SSL = SSL_new(g_Ctx);
        SSL_set_fd(g_Con_SSL, g_ClientSocket);
        if(g_ClientSocket == SERROR)
        {
            err = WSAGetLastError();
            fprintf(stderr, "accept : %d", err);
            return err;
        }
        vector_add(&g_Clients, SOCKET, g_ClientSocket);
        vector_add(&g_Clients_SSL, SSL*, g_Con_SSL);
        
    }
    vector_free(g_Clients);
    vector_free(g_Clients_SSL);
    SSL_CTX_free(g_Ctx);
    return 0;
}

void ClientHandler()
{
    // gets the current client's socket handle / ssl connection hopefully before a new client connects
    SOCKET thisClient =  g_ClientSocket;
    SSL* ssl          =  g_Con_SSL;
    int index = vector_size(g_Clients_SSL);
    char* buf = calloc(512, sizeof(char));
    int ret = 0, err = 0;
    puts("Client connected!");
    ret = SSL_accept(ssl);
    if (ret <= 0) 
    {
        err = SSL_get_error(ssl, ret);
        printf("SSL_accept failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
        shutdown(thisClient, SD_BOTH);
        goto end;
    }
    puts("SSL initalized!");
    bool signedIn = false;
    char* username = calloc(128, sizeof(char));
    size_t msgSize = 512;
    while(true)
    {
        memset(buf, '\0', 512);
        ret = SSL_read(ssl, buf, 512);
        if(ret <= 0)
        {
            err = SSL_get_error(ssl, ret);
            printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
            if (err == SSL_ERROR_SYSCALL)
            {
                err = WSAGetLastError();
                if (err == 0)
                    perror("err = SSL_ERROR_SYSCALL");
                else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                break;
            }
            shutdown(thisClient, SD_BOTH);
            break;
        }
        if (_stricmp(buf, "CHAT_PROTOCOL_SIGNIN") == 0)
        {
            if (signedIn)
            {
                SSL_write(ssl, "Wait! You already signed in >:(. You thought I was that stupid to not keep a log if the user is already signed in?", 114);
                continue;
            }
            signedIn = true;
            char* hash = calloc(256, sizeof(char));
            // receive username
            ret = SSL_read(ssl, username, 128);
            if (ret <= 0)
            {
                err = SSL_get_error(ssl, ret);
                printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                if (err == SSL_ERROR_SYSCALL)
                {
                    err = WSAGetLastError();
                    if (err == 0)
                        perror("err = SSL_ERROR_SYSCALL");
                    else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                    break;
                }
                shutdown(thisClient, SD_BOTH);
                break;
            }
            ret = SSL_read(ssl, hash, 255);
            if (ret <= 0)
            {
                err = SSL_get_error(ssl, ret);
                printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                if (err == SSL_ERROR_SYSCALL)
                {
                    err = WSAGetLastError();
                    if (err == 0)
                        perror("err = SSL_ERROR_SYSCALL");
                    else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                    break;
                }
                shutdown(thisClient, SD_BOTH);
                break;
            }
            char* truePassword = calloc(256, sizeof(char));
            MapGet(username, truePassword, 255);
            if (_stricmp(truePassword, "") == 0)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_DOESNT_EXIST", 26);
                shutdown(thisClient, SD_BOTH);
                ExitThread(ERROR_FILE_NOT_FOUND);
            }
            else if (_stricmp(hash, truePassword) == 0)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_AUTHENTICATED", 28); // User entered the right password
            }
            else
            {
                SSL_write(ssl, "CHAT_PROTOCOL_INVALID_PASSWORD", 30);
                shutdown(thisClient, SD_BOTH);
                ExitThread(ERROR_ACCESS_DENIED);
            }
            free(hash);
            free(truePassword);
            msgSize += (strlen(buf) + 2);
            int sz = strlen(username) + 22;
            char* joinMsg = calloc(sz, sizeof(char));
            sprintf_s(joinMsg, sz, "%s has joined the chat!", username);
            EchoMessage(joinMsg, sz);
            free(joinMsg);
            continue;
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_SIGNUP") == 0)
        {
            if (signedIn)
            {
                SSL_write(ssl, "Wait! You already signed in >:(. You thought I was that stupid to not keep a log if the user is already signed in?", 114);
                continue;
            }
            signedIn = true;
            char* hash = calloc(256, sizeof(char));
            ret = SSL_read(ssl, username, 128);
            if (ret <= 0)
            {
                err = SSL_get_error(ssl, ret);
                printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                if (err == SSL_ERROR_SYSCALL)
                {
                    err = WSAGetLastError();
                    if (err == 0)
                        perror("err = SSL_ERROR_SYSCALL");
                    else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                    break;
                }
                shutdown(thisClient, SD_BOTH);
                break;
            }
            ret = SSL_read(ssl, hash, 256);
            if (ret <= 0)
            {
                err = SSL_get_error(ssl, ret);
                printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
                if (err == SSL_ERROR_SYSCALL)
                {
                    err = WSAGetLastError();
                    if (err == 0)
                        perror("err = SSL_ERROR_SYSCALL");
                    else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
                    break;
                }
                shutdown(thisClient, SD_BOTH);
                break;
            }
            char data[64] = { 0 };
            MapGet(username, data, 64);
            if (strlen(data) != 0)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_ALREADY_EXISTS", 29);
                break;
            }
            // Adding username and hash to the data map
            AddToMap(username, hash);
            FILE* file = fopen("credentials.txt", "a");
            fprintf_s(file, "{ %s, %s }\n", username, hash); // Writes the username and hash to the file
            fclose(file);
            int sz = strlen(username) + 10;
            char* joinMsg = calloc(sz, sizeof(char));
            sprintf_s(joinMsg, sz, "Welcome %s!", username);
            EchoMessage(joinMsg, sz);
            free(joinMsg); 
            continue;
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_SHUTDOWN") == 0)
        {
            SSL_shutdown(ssl);
            shutdown(thisClient, SD_BOTH);
            closesocket(thisClient);
            break;
        }
        if (strlen(username) == 0)
        {
            SSL_write(ssl, "Heyo! You made an account with no username? Get outta here!", 60);
            shutdown(thisClient, SD_BOTH);
            break;
        }
        char* msg = calloc(msgSize, sizeof(char));
        sprintf_s(msg, msgSize, "[%s] %s", username, buf);
        // Send it to all the clients
        EchoMessage(msg, strlen(msg));
        free(msg);
    }
end:
    __try
    {
        vector_remove(&g_Clients, index - 1);
        vector_remove(&g_Clients_SSL, index - 1);
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
    {
        puts("Whoops! I tried to access a wrong memory address.");
    }
    g_ClientCount--;
    puts("Closed connection to client!");
    msgSize = strlen(username) + 19;
    char* msg = calloc(msgSize, sizeof(char));
    sprintf_s(msg, msgSize, "%s has left the game", username);
    EchoMessage(msg, msgSize);
    free(msg);
    free(buf);
    free(username);
    ExitThread(err);
}
void EchoMessage(const void* buffer, int sizeInBytes)
{
    for (int i = 0; i < vector_size(g_Clients_SSL); i++)
    {
        if (SSL_write(g_Clients_SSL[i], buffer, sizeInBytes) <= 0)
        {
            continue;
        }
    }
}
bool AppendToString(char ch, char** buffer, size_t size)
{
    char* backup = _recalloc(*buffer, size + 1, sizeof(char));
    if (backup == NULL) return false;
    *buffer = backup;
    (*buffer)[size - 1] = ch;
    return true;
}
char* getline(FILE* stream, int* len)
{
    char ch = '\0';
    char* str = calloc(1, sizeof(char));
    void* backup = NULL;
    while (true)
    {
        ch = getc(stream);
        if (ch == '\n' || ch == (signed int)'\xFF') break; // if the character read != a newline or EOF (aka -1 or 0xFF) then break
        (*len)++;
        backup = _recalloc(str, (*len) + 1, sizeof(char));
        if (backup == NULL) break;
        str = backup;
        str[(*len) - 1] = ch;
    }
    if (*len != 0) return str;
    free(str);
    *len = 0;
    return NULL;
}
void AddToMap(char* key, char* hash)
{
    p_password_map s;
    s = malloc(sizeof *s);
    s->username = key;
    s->password = hash;
    HASH_ADD_STR(g_ClientPasswords, username, s);
}
void MapGet(char* key, char* data, size_t bufsize)
{
    p_password_map s;
    HASH_FIND_STR(g_ClientPasswords, key, s);
    if (s == NULL) { strcpy_s(data, 1, ""); return; }
    strcpy_s(data, bufsize, s->password);
}
bool ParameterHandler(enum paramflags* flag, int i, char** str1, int* int1)
{
    char** argv = __argv;
    switch (*flag)
    {
    case DEFAULT:
        return false;
    case FPORT:
        *int1 = atoi(argv[i + 1]);
        *flag = READ;
        break;
    case FIP:
        *str1 = argv[i + 1];
        *flag = READ;
        break;
    case FCERTFNAME:
        *str1 = argv[i + 1];
        *flag = READ;
        break;
    case FPRIVATEKEYFNAME:
        *str1 = argv[i + 1];
        *flag = READ;
        break;
    case FHELP:
        help:
        printf("Commands are: \n--port - the port to be used\n--ip the ip the server should bind to\n--certificate_fname - the certificate filename\n--privatekey_fname - the private key's filename\n--help, -h show this menu\nNote: if none of these arguments are used server will bind to\nlocalhost:443 and will try to read cert.pem and key.pem\n");
        break;
    case INVALID:
        goto help;
        break;
    default:
        break;
    }
    return true;
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

void GetClientIdsFromFile(FILE* stream)
{
    char ch = '\0';
    char* str = NULL;
    char* username = calloc(1, sizeof(char)), *hash = calloc(1, sizeof(char));
    int len = 0;
    int unameLen = 1, hashLen = 1;
    bool firstIteration = true;
    while (true)
    {
        str = getline(stream, &len);
        if (len == 0) { free(str); break; } // if the file stream was at EOF
        if (firstIteration && len == 0 && strlen(str) == 0) break;
        for (int i = 3; ch != ','; i++)
        {
            AppendToString(ch = str[i - 1], &username, unameLen);
            unameLen++;
        }
        username[unameLen - 2] = 0;
        for (int i = unameLen + 2; ch != '}'; i++)
        {
            AppendToString(ch = str[i], &hash, hashLen);
            hashLen++;
        }
        hash[hashLen - 3] = 0;
        AddToMap(username, hash);
        free(str);
        firstIteration = false;
        len = 0;
    }
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
void configure_context(SSL_CTX* ctx, char* keyfname, char* certfname)
{
    int ret = 0, err = 0;
    /* Set the key and cert */
    ret = SSL_CTX_use_certificate_file(ctx, certfname, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        err = ERR_get_error();
        printf("SSL_CTX_use_certificate_file failed with exit code : %d", err);
        exit(err);
    }
    ret = SSL_CTX_use_PrivateKey_file(ctx, keyfname, SSL_FILETYPE_PEM);
    if (ret <= 0) {
        err = ERR_get_error();
        printf("SSL_CTX_use_PrivateKey_file failed with exit code : %d", err);
        exit(err);
    }
}

BOOL WINAPI HandlerRoutine(__in DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
        printf("Received ctrl+c! Closing connections with all clients...");
        if (g_ClientCount == 0) goto done;
        for (int i = 0; i < vector_size(g_Clients); i++)
        {
            shutdown(g_Clients[i], SD_BOTH);
            SSL_shutdown(g_Clients_SSL[i]);
        }
        done:
        printf("Done! Closing now.");
        ExitProcess(0);
        return TRUE;
    case CTRL_BREAK_EVENT:
        printf("Received ctrl+break! Closing connections with all clients...");
        if (g_ClientCount == 0) goto done1;
        for (int i = 0; i < vector_size(g_Clients); i++)
        {
            shutdown(g_Clients[i], SD_BOTH);
        }
        done1:
        printf("Done! Closing now.");
        ExitProcess(0);
        return TRUE;
    case CTRL_CLOSE_EVENT:
        printf("Received close signal! Shuting down connections with all clients...");
        if (g_ClientCount == 0) goto done2;
        for (int i = 0; i < vector_size(g_Clients); i++)
        {
            shutdown(g_Clients[i], SD_BOTH);
        }
        done2:
        printf("Done! Closing now.");
        ExitProcess(0);
        return TRUE;
    default:
        break;
    }
    return FALSE;
}
