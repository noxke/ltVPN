#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "tlsserver.h"
#include "vpnserver.h"
#include "config.h"
#include "user.h"
#include "logger.h"

// 解析命令行参数
void print_help() {
    printf("Usage: ltvpn-server <run/add_user> [options]\n");
    printf("Options:\n");
    printf("  -c <dir>   Specify the configuration directory\n");
    printf("  -d         Run in daemon mode\n");
    printf("  -h         Print this help message and exit\n");
}

int parser_parms(int argc, const char *argv[]) {    
    if (argc < 2) {
        print_help();
        return -1;
    }

    const char *command = argv[1];
    if (strcmp(command, "run") == 0) {
        server_mode = SERVER_RUN;
    }
    else if (strcmp(command, "add_user") == 0)
    {
        server_mode = ADD_USER;
    }
    else
    {
        fprintf(stderr, "Error: Invalid command '%s'.\n", command);
        print_help();
        return -1;
    }

    int opt;
    const char *config_dir = NULL;

    // 使用 getopt 解析命令行参数，从 argv[2] 开始
    while ((opt = getopt(argc - 1, (char * const *)argv + 1, "hcd:m:")) != -1) {
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
    if (parser_parms(argc, argv) != 0 || parser_config(SERVER_CONF) != 0)
    {
        return -1;
    }

    switch (server_mode)
    {
        case ADD_USER:
            new_user();
            return 0;
            break;
        case SERVER_RUN:
            break;
        default:
            return -1;
    }
    
    // 初始化VPN服务器
    if (initVPNServer() < 0)
    {
        return -1;
    }

    struct sockaddr_in sa_client;
    socklen_t client_len = sizeof(sa_client);

    // 初始化TLS上下文
    ssl_ctx = setupTLSCTX();
    // 创建TCP监听端口
    listen_sock = setupTCPServer(server_port);

    while (1) {
        int sock = accept(listen_sock, (struct sockaddr *) &sa_client, &client_len);

        if (sock == -1) {
            fprintf(stderr, "Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
            continue;
        }
        // 创建子线程处理新连接 避免阻塞
        pthread_t thread;
        SSL* ssl = SSL_new(ssl_ctx);
        SSL_set_fd(ssl, sock);
        if (pthread_create(&thread, NULL, newVPNClient, (void *)ssl) != 0) {
            fprintf(stderr, "Thread creation failed");
        }
    }

    return 0;
}