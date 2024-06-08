#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "tlsclient.h"
#include "vpnclient.h"
#include "config.h"
#include "user.h"
#include "logger.h"

// 解析命令行参数
void print_help() {
    printf("Usage: ltvpn-client [options]\n");
    printf("Options:\n");
    printf("  -c <dir>   Specify the configuration directory\n");
    printf("  -d         Run in daemon mode\n");
    printf("  -h         Print this help message and exit\n");
}

int parser_parms(int argc, const char *argv[]) {    
    int opt;
    const char *config_dir = NULL;

    // 使用 getopt 解析命令行参数
    while ((opt = getopt(argc, (char * const *)argv, "hcd:m:")) != -1) {
        switch (opt) {
            case 'h':
                print_help();
                return 0;
            case 'c':
                config_dir = optarg;
                break;
            case 'd':
                daemon(1, 1);
                break;
            default:
                print_help();
                return -1;
        }
    }

    // 设置配置目录
    struct stat info;
    if (config_dir) {
        // 检查目录是否存在
        if (stat(config_dir, &info) != 0 || !S_ISDIR(info.st_mode))
        {
            fprintf(stderr, "Directory '%s' does not exist.\n", config_dir);
            return -1;
        }
        snprintf(config_path, sizeof(config_path), "%s", config_dir);
    }
    else if (stat(DEFAULT_CONFIG_PATH1, &info) == 0 && S_ISDIR(info.st_mode))
    {
        snprintf(config_path, sizeof(config_path), "%s", DEFAULT_CONFIG_PATH1);
    }
    else if (stat(DEFAULT_CONFIG_PATH2, &info) == 0 && S_ISDIR(info.st_mode))
    {
        snprintf(config_path, sizeof(config_path), "%s", DEFAULT_CONFIG_PATH2);
    }
    else
    {
        fprintf(stderr, "Configuration directory does not exist.\n");
        return -1;
    }
    return 0;
}

int main(int argc, const char *argv[])
{
    if (parser_parms(argc, argv) != 0 || parser_config(CLIENT_CONF) != 0)
    {
        return -1;
    }
    
    SSL *ssl = setupTLSClient(server_host);
    int sock = setupTCPClient(server_host, server_port);

    CHK_NULL(ssl);
    SSL_set_fd(ssl, sock);
    int err = SSL_connect(ssl);
    CHK_SSL(err);

    logger("SSL connection is successful\n");
    logger("SSL connection using %s\n", SSL_get_cipher(ssl));

    vpnClientMain(ssl);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    return 0;
}