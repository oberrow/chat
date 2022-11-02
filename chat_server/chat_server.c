#include <stdio.h>
#include <conio.h>
#include "boolean_type.h"
#include <vec.h>
#include <utarray.h>
#include <argon2.h>
#include <winsock2.h>
#include <openssl\ssl.h>
#include <openssl\err.h>
#include <map.h>
#include "dbInterface.h"
#include "User.h"

#pragma comment(lib, "Ws2_32.lib")

// Chat Protocol Version
// Changes with every protocol change
#define PROTOCOL_VERSION 0x02ui8
// The client is outdated
#define ERROR_CLIENT_VERSION_OUTDATED -60000i64
// The server is outdated
#define ERROR_SERVER_VERSION_OUTDATED -60001i64

#define SERROR INVALID_SOCKET

#pragma warning(disable : 6387)

SOCKET               g_ServerSocket;
SOCKET               g_ClientSocket;
SSL*                 g_Con_SSL = NULL;
struct sockaddr      g_ClientAddress;
SOCKET*              g_Clients;
SSL**                g_Clients_SSL;
DB*                  g_DB;
UT_array*            g_ClientsUname;
uint16_t*            g_Salt;
char    *            g_SaltFname = "salt.bin";
SSL_CTX*             g_Ctx;
uint64_t             g_ClientCount = 0;
char*                g_CredFname = "credentials.db";

void ClientHandler();
void EchoMessage(const void* buffer, int sizeInBytes);
bool AppendToString(char ch, char** buffer, size_t size);
char* getline(FILE* stream, int* len);
bool ParameterHandler(enum paramflags* flag, int element, char** str1, int* int1);
BOOL MByteToUnicode(LPCSTR  multiByteStr, LPWSTR unicodeStr,    DWORD size);
BOOL UnicodeToMByte(LPCWSTR unicodeStr,   LPSTR  multiByteStr,  DWORD size);
void GetSaltFromFile(FILE* stream);
const char* ParseStructIntoString(ClientData c, int* len);
ClientData  ParseStringIntoStruct(const char* c);
void ParseCommands();
// Next 2 functions taken from https://wiki.openssl.org/index.php/Simple_TLS_Server
SSL_CTX *create_context();
void configure_context(SSL_CTX *ctx, char* keyfname, char* certname);
// https://learn.microsoft.com/en-us/windows/console/handlerroutine
BOOL WINAPI HandlerRoutine(
    _In_ DWORD dwCtrlType
);

enum paramflags
{
    INVALID = -1, // an invalid option was specified
    DEFAULT, // default flag
    READ, // Start reading from the next argument
    FPORT, // --port was specified
    FIP, // --ip was specified
    FCERTFNAME, // --certificate_fname certificate file path
    FPRIVATEKEYFNAME, // --privatekey_fname the private key file path
    FCREDFNAME, // the filename of the clients credentials
    FSALTFNAME, // where the salt is located
    FMAKESALT, // whether to make the salt or not ** WILL INVALIDATE ALL PASSWORDS **
    FHELP, // --help, -h
};

int main(int argc, char **argv, char **envp)
{
    int err = 0;
    /*OpenDB("credentials.db", 0, DB_BTREE, &g_DB, &err);
    DBC* cursor;
    g_DB->cursor(g_DB, NULL, &cursor, 0);
    DBT key, data;
    memset(&key, 0, sizeof(DBT));
    memset(&data, 0, sizeof(DBT));
    while ((err = cursor->get(cursor, &key, &data, DB_NEXT)) == 0) {
        printf_s("%s:%s", key.data, data.data);
    }
    cursor->close(cursor);
    return 0;*/
    SetConsoleCtrlHandler(HandlerRoutine, TRUE);
    g_Clients = vector_create();
    g_Clients_SSL = vector_create();
    utarray_new(g_ClientsUname, &ut_str_icd);
    enum paramflags par = DEFAULT;
    int port = 443;
    char* ip = "127.0.0.1";
    char* certname = "cert.pem";
    char* privkeyname = "key.pem";
    char** funcpar = NULL;
    g_Salt = calloc(32, sizeof(uint16_t));
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
        else if (_stricmp(element, "--credentials_fname") == 0)
        {
            par = FCREDFNAME;
            ParameterHandler(&par, i, &g_CredFname, NULL);
        }
        else if (_stricmp(element, "--salt_fname") == 0)
        {
            par = FSALTFNAME;
            ParameterHandler(&par, i, &g_SaltFname, NULL);
        }
        else if (_stricmp(element, "--make_salt") == 0)
        {
            par = FMAKESALT;
            ParameterHandler(&par, i, &g_Salt, NULL);
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
    FILE* test = fopen(g_CredFname, "r");
    if(!test) if (!OpenDB(g_CredFname, DB_CREATE, DB_BTREE, &g_DB, &err)) return err;
    if(test) fclose(test);
    //if(test) OpenDB("credentials.db", 0, DB_BTREE, &g_DB, &err);
    //DBC* cursor;
    //g_DB->cursor(g_DB, NULL, &cursor, 0);
    //DBT key, data;
    //memset(&key, 0, sizeof(DBT));
    //memset(&data, 0, sizeof(DBT));
    //while ((err = cursor->get(cursor, &key, &data, DB_NEXT)) == 0) {
    //    ClientData c = *((ClientData*)data.data);
    //    // store the data in a vector or hashmap (failed)
    //    // ...
    //    // I could just reload the permisions every iteration
    //}
    //cursor->close(cursor);
    CloseDB(g_DB);
    if(SSL_library_init() < 0)
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    FILE* file = NULL;
    file = fopen(g_SaltFname, "r");
    if (file == NULL) return ERROR_FILE_NOT_FOUND;
    GetSaltFromFile(file);
    fclose(file);
    g_Ctx = create_context();
    configure_context(g_Ctx, privkeyname, certname);
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
    printf("Listening on port %d!\nProtocol Version is : 0x%02x\n", port, PROTOCOL_VERSION);
    if(listen(g_ServerSocket, SOMAXCONN) == SERROR)
    {
        err = WSAGetLastError();
        fprintf(stderr, "listen : %d", err);
        return err;
    }
    int i = 0;
    int cAddrLen = sizeof g_ClientAddress;
    auto threadHandle1 = _beginthread(ParseCommands, 0, NULL);
    CloseHandle(threadHandle1);
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
    DB* db = NULL;
    int index = vector_size(g_Clients_SSL);
    int uIndex = 0;
    int ret = 0, err = 0;
    puts("Client connected!");
    ret = SSL_accept(ssl);
    if (ret <= 0) 
    {
        err = SSL_get_error(ssl, ret);
        printf("SSL_accept failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
        shutdown(thisClient, SD_BOTH);
        ExitThread(err);
    }
    puts("SSL initalized!\nChecking Client Protocol Version!");
    int cProtVer = 0;
    ret = SSL_read(ssl, &cProtVer, sizeof(int)); // gets protocol version
    if (ret <= 0)
    {
        err = SSL_get_error(ssl, ret);
        printf("SSL_read failed! Check OpenSSL's documentation for more info on this error. Error code: %d, Line : %d\n", err, __LINE__);
        if (err == SSL_ERROR_SYSCALL)
        {
            err = WSAGetLastError();
            if (err == 0)
                perror("err = SSL_ERROR_SYSCALL ");
            else printf("err = SSL_ERROR_SYSCALL WSAGetLastError is : %d\n", err);
            ExitThread(err);
        }
        shutdown(thisClient, SD_BOTH);
        ExitThread(err);
    }
    cProtVer = ntohs(cProtVer);
    if (cProtVer < PROTOCOL_VERSION)
    {
        printf_s("Error! Client is outdated! Error code: %lld\n", ERROR_CLIENT_VERSION_OUTDATED);
        SSL_write(ssl, "CHAT_ERROR_CLIENT_VERSION_OUTDATED", 34);
        ExitThread(ERROR_CLIENT_VERSION_OUTDATED);
    }
    else if (cProtVer > PROTOCOL_VERSION)
    {
        printf_s("Error! Server is outdated or the client is using a higher version that doesn't exist! Error code: %lld\n", ERROR_SERVER_VERSION_OUTDATED);
        SSL_write(ssl, "CHAT_ERROR_SERVER_VERSION_OUTDATED", 34);
        ExitThread(ERROR_SERVER_VERSION_OUTDATED);
    }
    SSL_write(ssl, "CHAT_PROTOCOL_VERSION_MATCH", 28);
    puts("Protocol Version Matched!");
    if (!OpenDB("credentials.db", 0, DB_BTREE, &db, &err))
    {
        printf_s("Error! Cannot open database! Error code : %d! See https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbopen.html for more info!\n", err);
        ExitThread(err);
    }
    bool signedIn = false, joinedMsg = false;
    puts("Opening chatlog");
    FILE* chatlog = fopen("chatlog.log", "a");
    puts("Done!");
    char* username = calloc(129, sizeof(char));
    char* buf = calloc(512, sizeof(char));
    char* cliDat = calloc(256, sizeof(char));
    size_t msgSize = 512;
    ClientData c, c2;
    memset(&c , 0, sizeof(ClientData));
    memset(&c2, 0, sizeof(ClientData));
    char* perm_str = calloc(7, sizeof(char));
    strcpy_s(perm_str, 7, "NORMAL");
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
            char* pwd = calloc(256, sizeof(char));
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
            utarray_push_back(g_ClientsUname, &username);
            uIndex = utarray_len(g_ClientsUname);
            ret = SSL_read(ssl, pwd, 255);
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
            argon2id_hash_encoded(2, (1 << 16), 2, pwd, strlen(pwd), g_Salt, 32, 96, hash, 255);
            SecureZeroMemory(pwd, 256);
            free(pwd);
            bool contains = false;
            if (!ContainsKey(db, username, 256, &contains, &err))
            {
                printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbget.html to find out what the error code means!\n", err);
                break;
            }
            int len = 256;
            char* str = calloc(256, sizeof(char));
            if (contains)
                if (!ReadDB(username, str, &len, db, &err))
                {
                    printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbget.html to find out what the error code means!\n", err);
                    break;
                }
            c = ParseStringIntoStruct(str);
            if (!contains)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_DOESNT_EXIST", 26);
                shutdown(thisClient, SD_BOTH);
                free(hash);
                SecureZeroMemory(&c, sizeof(c));
                err = ERROR_FILE_NOT_FOUND;
                break;
            }
            else if (stricmp(hash, c.password) == 0)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_AUTHENTICATED", 27);
            }
            else
            {
                SSL_write(ssl, "CHAT_PROTOCOL_INVALID_PASSWORD", 30);
                shutdown(thisClient, SD_BOTH);
                SecureZeroMemory(hash, 256);
                free(hash);
                SecureZeroMemory(&c, sizeof(c));
                err = ERROR_ACCESS_DENIED;
                break;
            }
            free(hash);
            switch (c.permmissions)
            {
            case perm_mute:
                strcpy(perm_str, "MUTE");
                break;
            case perm_normal:
                strcpy(perm_str, "NORMAL");
                break;
            case perm_all:
                strcpy(perm_str, "OP");
                break;
            default:
                break;
            }
            if (!c.hasJoinedTwice) 
            {
                c.hasJoinedTwice = true;
                int l = 0;
                const char* toWrite = ParseStructIntoString(c, &l);
                if (!DeleteKey(db, username, &err))
                {
                    printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbdel.html to find out what the error code means!\n", err);
                    free(toWrite);
                    break;
                }
                if (!WriteDB(username, toWrite, l, db, 0, &err))
                {
                    printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbput.html to find out what the error code means!\n", err);
                    free(toWrite);
                    break;
                }
                db->sync(db, 0);
                free(toWrite);
            }
            SecureZeroMemory(c.password, strlen(c.password));
            free(c.password);
            msgSize += (strlen(buf) + 2);
            int sz = strlen(username) + 22;
            char* joinMsg = calloc(sz, sizeof(char));
            sprintf_s(joinMsg, sz, "%s has joined the chat!", username);
            EchoMessage(joinMsg, sz);
            printf_s("%s\n", joinMsg);
            fprintf_s(chatlog, "%s\n", joinMsg);
            free(joinMsg);
            fflush(chatlog);
            joinedMsg = true;
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
            char* pwd  = calloc(256, sizeof(char));
            char* hash = calloc(256, sizeof(char));
            ret = SSL_read(ssl, username, 128);
            utarray_push_back(g_ClientsUname, &username);
            uIndex = utarray_len(g_ClientsUname);
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
            ret = SSL_read(ssl, pwd, 256);
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
            argon2id_hash_encoded(2, (1 << 16), 2, pwd, strlen(pwd), g_Salt, 32, 96, hash, 255);
            free(pwd);
            bool contains = false;
            if (!ContainsKey(db, username, 256, &contains, &err))
            {
                printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbget.html to find out what the error code means!\n", err);
                break;
            }
            int len = sizeof(ClientData);
            memset(&c, 0, len);
            c.password = hash;
            c.hasJoinedTwice = false;
            c.permmissions = perm_normal;
            int l = 0;
            const char* parsed = ParseStructIntoString(c, &l);
            if (contains)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_ALREADY_EXISTS", 28);
                break;
            }
            if (!WriteDB(username, parsed, l, db, DB_NOOVERWRITE, &err))
            {
                printf_s("Error while writing to the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbput.html to find out what the error code means!\n", err);
                break;
            }
            SecureZeroMemory(c.password, l);
            free(c.password);
            int sz = strlen(username) + 10;
            char* joinMsg = calloc(sz, sizeof(char));
            sprintf_s(joinMsg, sz, "Welcome %s!", username);
            EchoMessage(joinMsg, sz);
            printf_s("%s\n", joinMsg);
            fprintf_s(chatlog, "%s\n", joinMsg);
            fflush(chatlog);
            free(joinMsg);
            free(parsed);
            joinedMsg = true;
            db->sync(db, 0);
            continue;
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_REMOVE") == 0 && signedIn /*to make sure that a hacked client doesn't send the message to crash the server*/)
        {
            char* pwd = calloc(256, 1);
            char* truePwd = calloc(256, 1);
            char* hash = calloc(256, 1);
            ret = SSL_read(ssl, pwd, 255);
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
                free(truePwd);
                free(hash);
                free(pwd);
                break;
            }
            argon2id_hash_encoded(2, (1 << 16), 2, pwd, strlen(pwd), g_Salt, 32, 96, hash, 255);
            SecureZeroMemory(pwd, 256);
            free(pwd);
            int len = 255;
            if (!ReadDB(username, truePwd, &len, db, &err))
            {
                printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbget.html to find out what the error code means!\n", err);
                free(truePwd);
                free(hash);
                free(pwd);
                break;
            }
            c = ParseStringIntoStruct(truePwd);
            if (_stricmp(hash, c.password) == 0)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_AUTHENTICATED", 27);
                DeleteKey(db, username, &err);
                SSL_shutdown(ssl);
                shutdown(thisClient, SD_BOTH);
                SecureZeroMemory(c.password, 256);
                free(c.password);
                free(truePwd);
                free(hash);
                free(pwd);
                break;
            }
            else
            {
                SSL_write(ssl, "CHAT_PROTOCOL_INVALID_PASSWORD", 30);
                SecureZeroMemory(c.password, 256);
                free(c.password);
                free(truePwd);
                free(hash);
                free(pwd);
                continue;
            }
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_CHANGE_PWD") == 0 && signedIn)
        {
            char *pwd, *data, *hash;
            pwd = calloc(256, sizeof(char));
            data = calloc(256, sizeof(char));
            hash = calloc(256, sizeof(char));
            ret = SSL_read(ssl, pwd, 255);
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
                free(hash);
                free(data);
                free(pwd);
                break;
            }
            argon2id_hash_encoded(2, (1 << 16), 2, pwd, strlen(pwd), g_Salt, 32, 96, hash, 255);
            SecureZeroMemory(pwd, 256);
            int len = 255;
            if (!ReadDB(username, data, &len, db, &err))
            {
                printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbget.html to find out what the error code means!\n", err);
                free(hash);
                free(data);
                free(pwd);
                break;
            }
            c = ParseStringIntoStruct(data);
            free(data);
            data = NULL;
            if (_stricmp(c.password, hash) == 0)
            {
                SSL_write(ssl, "CHAT_PROTOCOL_AUTHENTICATED", 28);
            }
            else
            {
                SSL_write(ssl, "CHAT_PROTOCOL_INVALID_PASSWORD", 31);
                continue;
            }
            // the new password
            ret = SSL_read(ssl, pwd, 255);
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
                free(c.password);
                free(hash);
                free(data);
                free(pwd);
                break;
            }
            argon2id_hash_encoded(2, (1 << 16), 2, pwd, strlen(pwd), g_Salt, 32, 96, hash, 255);
            SecureZeroMemory(pwd, 256);
            free(pwd); // we needed pwd for longer but now we can free it
            pwd = NULL;
            SecureZeroMemory(c.password, 256);
            for (int i = 0; i < strlen(hash); i++) c.password[i] = hash[i];
            data = ParseStructIntoString(c, &len);
            free(c.password);
            c.password = NULL;
            if (!DeleteKey(db, username, &err))
            {
                printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbdel.html to find out what the error code means!\n", err);
                free(c.password);
                free(hash);
                free(data);
                free(pwd);
                break;
            }
            if (!WriteDB(username, data, len, db, 0, &err))
            {
                printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbput.html to find out what the error code means!\n", err);
                free(c.password);
                free(hash);
                free(data);
                free(pwd);
                break;
            }
            db->sync(db, 0);
            free(c.password);
            free(hash);
            free(data);
            free(pwd);
            continue;
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_SHUTDOWN") == 0)
        {
            SSL_shutdown(ssl);
            shutdown(thisClient, SD_BOTH);
            closesocket(thisClient);
            break;
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_WHOAMI") == 0)
        {
            SSL_write(ssl, username, strlen(username));
            fprintf_s(chatlog, "CHAT_PROTOCOL_WHOAMI:%s\n", username);
            printf_s("CHAT_PROTOCOL_WHOAMI:%s\n", username);
            continue;
        }
        else if (_stricmp(buf, "CHAT_PROTOCOL_LISTONLINEUSERS") == 0)
        {
            char** p = NULL;
            while ((p = (char**)utarray_next(g_ClientsUname, p)))
            {
                SSL_write(ssl, *p, strlen(*p));
                fprintf_s(chatlog, "CHAT_PROTOCOL_LISTONLINEUSERS:%s\n", *p);
                printf_s("CHAT_PROTOCOL_LISTONLINEUSERS:%s\n", *p);

            }
            continue;
        }
        if (strlen(username) == 0)
        {
            SSL_write(ssl, "Heyo! You made an account with no username? Get outta here!", 60);
            shutdown(thisClient, SD_BOTH);
            break;
        }
        int len = 0xFF;
        CloseDB(db);
        if (!OpenDB("credentials.db", 0, DB_BTREE, &db, &err))
        {
            printf_s("Error! Cannot open database! Error code : %d! See https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbopen.html for more info!\n", err);
            ExitThread(err);
        }
        if (!ReadDB(username, cliDat, &len, db, &err))
        {
            printf_s("Error while reading from the database! Error code : %d.\nGo to https://docs.oracle.com/cd/E17276_01/html/api_reference/C/dbget.html to find out what the error code means!\n", err);
            break;
        }
        c2 = ParseStringIntoStruct(cliDat);
        if (c2.permmissions != c.permmissions)
        {
            c.permmissions = c2.permmissions;
            switch (c.permmissions)
            {
            case perm_mute:
                strcpy(perm_str, "MUTE");
                break;
            case perm_normal:
                strcpy(perm_str, "NORMAL");
                break;
            case perm_all:
                strcpy(perm_str, "OP");
                break;
            default:
                break;
            }
        }
        SecureZeroMemory(c2.password, 256);
        free(c2.password);
        memset(&c2, 0, sizeof(ClientData));
        char* msg = calloc(msgSize, sizeof(char));
        sprintf_s(msg, msgSize, "[%s] %s", username, buf);
        // Send it to all the clients
        if(c.permmissions != perm_mute) EchoMessage(msg, strlen(msg));
        printf_s("[%s] %s\n", perm_str, msg);
        fprintf_s(chatlog, "[%s] %s\n", perm_str, msg);
        fflush(chatlog);
        free(msg);
    }
end:
    __try
    {
        vector_remove(&g_Clients, index - 1);
        vector_remove(&g_Clients_SSL, index - 1);
        utarray_erase(g_ClientsUname, uIndex - 1, 1);
    }
    __except (GetExceptionCode() == STATUS_ACCESS_VIOLATION)
    {
        puts("Whoops! I tried to access an invalid memory address.");
    }
    g_ClientCount--;
    if (strlen(username) != 0 && joinedMsg)
    {
        msgSize = strlen(username) + 19;
        char* msg = calloc(msgSize, sizeof(char));
        sprintf_s(msg, msgSize, "%s has left the chat", username);
        EchoMessage(msg, msgSize);
        printf_s("%s\n", msg);
        fprintf_s(chatlog, "%s\n", msg);
        fflush(chatlog);
        free(msg);
    }
    puts("Closed connection to client!\nFreeing Allocated Buffer!");
    free(buf);
    free(username);
    free(cliDat);
    free(perm_str);
    puts("Closing the chatlog!");
    fclose(chatlog);
    puts("Closing the Database!");
    CloseDB(db);
    printf_s("Exiting Thread with code : %d", err);
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
bool ParameterHandler(enum paramflags* flag, int i, char** str1, int* int1)
{
    bool ret = true;
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
    case FCREDFNAME:
        *str1 = argv[i + 1];
        *flag = READ;
        break;
    case FSALTFNAME:
        *str1 = argv[i + 1];
        *flag = READ;
        break;
    case FMAKESALT:
        srand(time(NULL));
        uint16_t* salt = str1;
        FILE* file = fopen(g_SaltFname, "w");
        for (int i = 0; i < 32; i++)
        {
            salt[i] = rand() * 0x7FF % RAND_MAX;
            fprintf_s(file, "%d\n", salt[i]);
            fflush(file);
        }
        fclose(file);
        break;
    case FHELP:
        help:
        puts(
"Commands are: \n--port - the port to be used\n--ip the ip the server should bind to\n--certificate_fname - the certificate filename\
\n--privatekey_fname - the private key's filename\n--help, -h show this menu\n--credentials_fname the filename of where the credentials of clients are stored\
\nNote: if none of these arguments are specified the server will bind to\nlocalhost:443 and will try to use cert.pem and key.pem and credentials.txt\n");
        break;
    case INVALID:
        goto help;
        break;
    default:
        ret = false;
        break;
    }
    return ret;
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
void GetSaltFromFile(FILE* stream)
{
    int i = 0;
    char* sNum = NULL;
    int len = 0;
    while (true)
    {
        sNum = getline(stream, &len);
        if (sNum == NULL || strlen(sNum) == 0) { free(sNum); break; } // if eof
        g_Salt[i] = atoi(sNum);
        free(sNum);
        i++;
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
            SSL_shutdown(g_Clients_SSL[i]);
            shutdown(g_Clients[i], SD_BOTH);
        }
    done:
        printf("Closed Connections!\nClosing database 'credentials.db'!");
        printf("Done! Closing now.");
        ExitProcess(errno);
        return TRUE; // shouldn't ever be hit
    case CTRL_BREAK_EVENT:
        printf("Received ctrl+break! Closing connections with all clients...");
        if (g_ClientCount == 0) goto done1;
        for (int i = 0; i < vector_size(g_Clients); i++)
        {
            SSL_shutdown(g_Clients_SSL[i]);
            shutdown(g_Clients[i], SD_BOTH);
        }
        done1:
        printf("Closed Connections!\nClosing database 'credentials.db'!");
        printf("Done! Closing now.");
        ExitProcess(errno);
        return TRUE; // shouldn't ever be hit
    case CTRL_CLOSE_EVENT:
        printf("Received close signal! Shuting down connections with all clients...");
        if (g_ClientCount == 0) goto done2;
        for (int i = 0; i < vector_size(g_Clients); i++)
        {
            SSL_shutdown(g_Clients_SSL[i]);
            shutdown(g_Clients[i], SD_BOTH);
        }
    done2:
        printf("Closed Connections!\nClosing database 'credentials.db'!\n");
        printf("Done! Closing now.");
        ExitProcess(errno);
        return TRUE; // shouldn't ever be hit
    default:
        break;
    }
    return FALSE;
}

void ParseCommands()
{
    char* command = calloc(256, sizeof(char));
    char* subCommand = calloc(256, sizeof(char));
    int err = 0;
    DWORD numread = 0;
    while (true)
    {
        memset(command, 0, 256);
        memset(subCommand, 0, 256);
        ReadConsoleA(GetStdHandle(STD_INPUT_HANDLE), command, 255, &numread, NULL);
        command[strlen(command) - 2] = 0;
        for (int i = 0; i < strlen(command) && command[i] != ' '; i++)
        {
            subCommand[i] = command[i];
        }
        if (_stricmp(subCommand, "/stop") == 0)
        {
            _set_errno(0);
            HandlerRoutine(CTRL_CLOSE_EVENT); // call the callback function to end the program
        }
        else if (_stricmp(subCommand, "/incperm") == 0) // increments the permission level
        {
            char* target = strstr(command, " ") + 1;
            if (target == 0x01) continue;
            DB* db = NULL;
            if (!OpenDB("credentials.db", 0, DB_BTREE, &db, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            int len = 256;
            char* data = calloc(len, sizeof(char));
            bool contains = false;
            if (!ContainsKey(db, target, 256, &contains, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            if (!contains) continue;
            if (!ReadDB(target, data, &len, db, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            ClientData c = ParseStringIntoStruct(data);
            c.permmissions++;
            if (c.permmissions > 2) c.permmissions--;
            memset(data, 0, 256);
            free(data);
            data = NULL;
            int l = 0;
            data = ParseStructIntoString(c, &l);
            if (!DeleteKey(db, target, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            if (!WriteDB(target, data, strlen(data), db, 0, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            CloseDB(db);
            free(data);
            free(c.password);
        }
        else if(_stricmp(subCommand, "/decperm") == 0) // decrements the permission level
        {
            char* target = strstr(command, " ") + 1;
            if (target == 0x01) continue;
            DB* db = NULL;
            if (!OpenDB("credentials.db", 0, DB_BTREE, &db, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            int len = 256;
            char* data = calloc(len, sizeof(char));
            bool contains = false;
            if (!ContainsKey(db, target, 256, &contains, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            if (!contains) continue;
            if (!ReadDB(target, data, &len, db, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            ClientData c = ParseStringIntoStruct(data);
            c.permmissions--;
            if (c.permmissions < 0) c.permmissions++;
            memset(data, 0, 256);
            free(data);
            data = NULL;
            int l = 0;
            data = ParseStructIntoString(c, &l);
            if (!DeleteKey(db, target, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            if (!WriteDB(target, data, strlen(data), db, 0, &err)) { _set_errno(err); HandlerRoutine(CTRL_CLOSE_EVENT); }
            CloseDB(db);
            free(data);
            free(c.password);
        }
    }
    free(subCommand);
    free(command);
}

const char* ParseStructIntoString(ClientData c, int* len)
{
    // 8 + 2 + (strlen(c.password) + 1) + 3
    *len = 10 + (strlen(c.password) + 2) + 1;
    char* string = calloc(*len, sizeof(char));
    sprintf_s(string, 10 + (strlen(c.password) + 2) + 1, "%s`%d`%d", c.password, c.permmissions, c.hasJoinedTwice);
    return string;
}

ClientData  ParseStringIntoStruct(const char* c)
{
    ClientData cd;
    memset(&cd, 0, sizeof(ClientData));
    cd.password = calloc(256, sizeof(char));
    char temp[16];
    memset(temp, 0, 16);
    int i = 0;
    for (i = 0; i < strlen(c) && c[i] != '`'; i++)
    {
        cd.password[i] = c[i];
    }
    i++;
    int ci = 0;
    for (; i < strlen(c) && c[i] != '`'; i++)
    {
        temp[ci] = c[i];
    }
    cd.permmissions = atoi(temp);
    memset(temp, 0, 16);
    for (; i < strlen(c); i++)
    {
        temp[ci] = c[i];
        ci++;
    }
    cd.hasJoinedTwice = atoi(temp + 1);
    return cd;
}