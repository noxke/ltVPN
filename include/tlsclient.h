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

SSL *setupTLSClient(const char *hostname);
int setupTCPClient(const char *hostname, int port);