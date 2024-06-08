#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "tlsclient.h"
#include "config.h"
#include "logger.h"

int verify_callback(int preverify_ok, X509_STORE_CTX * x509_ctx)
{
    char buf[300];

    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);

    if (preverify_ok != 1) {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        logger("Verification failed: %s %s.\n", buf, X509_verify_cert_error_string(err));
    }
    return preverify_ok;
}

SSL *setupTLSClient(const char *hostname)
{
    // Step 0: OpenSSL library initialization 
    // This step is no longer needed as of version 1.1.0.
    SSL_library_init();
    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();

    const SSL_METHOD *meth;
    SSL_CTX *ctx;
    SSL *ssl;

    meth = SSLv23_client_method();
    ctx = SSL_CTX_new(meth);

    // 指定CA证书
    SSL_CTX_load_verify_locations(ctx, ca_cert, NULL);

    // 客户端校验服务器证书
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    ssl = SSL_new(ctx);

    X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    return ssl;
}

int setupTCPClient(const char *hostname, int port)
{
    struct sockaddr_in server_addr;

    // Get the IP address from hostname
    struct hostent *hp = gethostbyname(hostname);

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Fill in the destination information (IP, port #, and family)
    memset(&server_addr, '\0', sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    // Connect to the destination
    connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr));

    return sockfd;
}
