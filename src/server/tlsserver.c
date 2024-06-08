#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

#include "tlsserver.h"
#include "config.h"
#include "logger.h"

SSL_CTX *ssl_ctx = NULL;

// 处理口令输入
int password_callback(char *buf, int size, int rwflag, void *userdata) {
    strncpy(buf, server_passwd, size);
    return strlen(server_passwd);
}

SSL_CTX *setupTLSCTX()
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    // Step 1: SSL context initialization
    meth = SSLv23_server_method();
    ctx = SSL_CTX_new(meth);

    // 服务器不加载CA证书
    // SSL_CTX_load_verify_locations(ctx, ca_cert, NULL);

    // 服务器不校验证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Step 2: Set up the server certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // 设置使用默认口令
    SSL_CTX_set_default_passwd_cb(ctx, password_callback);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, NULL);
    if (SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the certificate public key\n");
        return NULL;
    }

    return ctx;
}

int setupTCPServer(int port)
{
    struct sockaddr_in sa_server;
    int listen_sock;

    listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_ERR(listen_sock, "socket");
    memset(&sa_server, '\0', sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(port);
    int err = bind(listen_sock, (struct sockaddr *) &sa_server, sizeof(sa_server));

    CHK_ERR(err, "bind");
    err = listen(listen_sock, 5);
    CHK_ERR(err, "listen");
    return listen_sock;
}
