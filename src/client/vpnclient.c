#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "config.h"
#include "logger.h"
#include "vpnclient.h"
#include "tlsclient.h"
#include "vpntun.h"
#include "user.h"

// #define WITH_DBG
#include "fd_dbg.h"

#define TUN_BUF_SIZE 2000

void vpnClientMain(SSL *ssl)
{
    // 客户端登陆
    char user_buf[USER_BUF_LEN];
    char network_record[USER_RECORD_LEN];
    if (input_user(user_buf, sizeof(user_buf)) != 0)
    {
        return;
    }
    SSL_write(ssl, user_buf, strlen(user_buf));
    int len = SSL_read(ssl, network_record, sizeof(network_record));
    if (len == 0)
    {
        logger("Login failed\n");
        return;
    }
    char *ip = network_record;
    char *network = strchr(ip, ':');
    if (network == NULL)
    {
        logger("Login failed\n");
        return;
    }
    *network = '\0';
    network++;

    // 创建tun设备
    int tun_fd = createVPNtun(ip);
    if (tun_fd < 0)
    {
        return;
    }
    // 添加路由
    char *token = strtok(network, ",");
    while (token != NULL)
    {
        if (routeAdd(network) == 0)
        {
            logger("Add route %s\n", network);
        }
        token = strtok(NULL, ",");
    }
    // vpn转发
    char buf[TUN_BUF_SIZE];
    int sock_fd = SSL_get_fd(ssl);
    while (1)
    {
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sock_fd, &readFDSet);
        FD_SET(tun_fd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(sock_fd, &readFDSet)) {
            // 客户端发给服务端数据 转发到tun设备
            int len = SSL_read(ssl, buf, sizeof(buf));
            if (len == 0)
            {
                break;
            }
            DBG_DUMP_SIMPLE("ssl->tun", buf, len);
            int ret = write(tun_fd, buf, len);
            if (ret < 0)
            {
                fprintf(stderr, "tunfd write() failed: (%d) %s", errno, strerror(errno));
                break;
            }
        }
        else if (FD_ISSET(tun_fd, &readFDSet))
        {
            // 服务器发送给客户端数据 转发到ssl
            int len = read(tun_fd, buf, sizeof(buf));
            DBG_DUMP_SIMPLE("tun->ssl", buf, len);
            SSL_write(ssl, buf, len);
        }
    }
}