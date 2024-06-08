#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define CHK_NULL(x)    if ((x)==NULL) exit (1)
#define CHK_ERR(err,s)    if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err)    if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

extern SSL_CTX *ssl_ctx;

SSL_CTX *setupTLSCTX();
int setupTCPServer(int port);