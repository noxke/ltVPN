#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

extern int listen_sock;
extern int tun_fd;

int initVPNServer();
void *newVPNClient(void *ssl_arg);
void *vpnServerTunThread(void *null_arg);