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
#include <netdb.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <pthread.h>

#include "config.h"
#include "logger.h"
#include "vpnserver.h"
#include "tlsserver.h"
#include "vpntun.h"
#include "user.h"

// #define WITH_DBG
#include "fd_dbg.h"

#define IP_POOL_SIZE 256  // IP池大小，适用于 /24 子网
#define TUN_BUF_SIZE 1500

int listen_sock = -1;
int tun_fd = -1;

// 客户端连接互斥锁
// 多个客户端分配IP或回收IP等操作时需要加锁
pthread_mutex_t client_lock;

// 全局客户端管道 用于子进程与副进程通信
int global_client_pipe[2];

// IP索引对应的客户端管道
int client_pipes[IP_POOL_SIZE][2];

typedef enum {
    AVAILABLE,
    RESERVED,
    USED
} ip_status_t;

typedef struct {
    uint32_t base_ip;
    uint32_t mask;
    int prefix_len;
    ip_status_t status[IP_POOL_SIZE];
} ip_pool_t;

ip_pool_t ip_pool;

// 解析 CIDR 字符串
int parse_cidr(const char *cidr, ip_pool_t *pool) {
    char ip_str[INET_ADDRSTRLEN];
    char *slash = strchr(cidr, '/');

    if (!slash) {
        return -1;
    }

    strncpy(ip_str, cidr, slash - cidr);
    ip_str[slash - cidr] = '\0';
    pool->prefix_len = atoi(slash + 1);

    if (inet_pton(AF_INET, ip_str, &pool->base_ip) != 1) {
        return -1;
    }

    pool->mask = htonl(~((1 << (32 - pool->prefix_len)) - 1));

    pool->base_ip &= pool->mask;
    return 0;
}

// 初始化 IP 池
int init_ip_pool(ip_pool_t *pool, const char *cidr) {
    if (parse_cidr(cidr, pool) < 0) {
        return -1;
    }

    for (int i = 0; i < IP_POOL_SIZE; i++) {
        pool->status[i] = AVAILABLE;
    }

    return 0;
}

// 获取 IP 地址在池中的索引
int get_ip_index(ip_pool_t *pool, const char *ip) {
    char ip_str[INET_ADDRSTRLEN];
    char *slash = strchr(ip, '/');
    if (slash != NULL) {
        strncpy(ip_str, ip, slash - ip);
        ip_str[slash - ip] = '\0';
    }
    else
    {
        strncpy(ip_str, ip, sizeof(ip_str));
    }

    struct in_addr addr;
    
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }

    if ((addr.s_addr & pool->mask) != (pool->base_ip & pool->mask)) {
        return -1;
    }

    int index = ntohl(addr.s_addr) - ntohl(pool->base_ip & pool->mask);
    return index;
}

// 标记 IP 地址为预留
int reserve_ip(ip_pool_t *pool, const char *ip) {
    int index = get_ip_index(pool, ip);
    if (index < 0 || index >= IP_POOL_SIZE) {
        return -1;
    }
    if (pool->status[index] == AVAILABLE)
    {
        pool->status[index] = RESERVED;
        return 0;
    }
    return -1;
}

// 获取下一个可用 IP 地址
int get_next_available_ip(ip_pool_t *pool, char *buf, size_t size) {
    char ip_str[INET_ADDRSTRLEN];
    for (int i = 1; i < IP_POOL_SIZE; i++) {  // 从1开始，避免分配网络地址
        if (pool->status[i] == AVAILABLE) {
            struct in_addr addr;
            addr.s_addr = htonl(ntohl(pool->base_ip) + i);
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            pool->status[i] = USED;
            snprintf(buf, size, "%s/%d", ip_str, pool->prefix_len);
            return 0;
        }
    }
    return -1;
}

// 回收 IP 地址
int reclaim_ip(ip_pool_t *pool, const char *ip) {
    int index = get_ip_index(pool, ip);
    if (index < 0 || index >= IP_POOL_SIZE) {
        return -1;
    }
    if (pool->status[index] == USED)
    {
        pool->status[index] = AVAILABLE;
        return 0;
    }
    return -1;
}

// 保留用户ip
int reserve_user_ip(ip_pool_t *pool)
{
    FILE *fp;
    char tmp_buf[USER_RECORD_LEN+1];

    fp = fopen(user_list_path, "rt");
    if (fp == NULL)
    {
        return -1;
    }
    while(1)
    {
        memset(tmp_buf, 0, sizeof(tmp_buf));
        int ret = fscanf(fp, "%256s", tmp_buf);
        if(ret == 0 || ret == EOF)
        {
            break;
        }
        char *token0 = strchr(tmp_buf, ':');
        *token0 = '\0';
        token0++;
        char *token1 = strchr(token0, ':');
        *token1 = '\0';
        token1++;
        char *token2 = strchr(token1, ':');
        *token2 = '\0';
        token2++;
        if (strlen(token1) == 0)
        {
            continue;
        }
        if (reserve_ip(&ip_pool, token1) == 0) {
            logger("Reserve ip %s for %s\n", token1, tmp_buf);
        } else {
            printf("Failed to reserve IP: %s\n", token1);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);
    return 0;
}

// 初始化服务器
int initVPNServer()
{
    char ip[IP_LEN];

    // 初始化全局管道
    pipe(global_client_pipe);
    // 初始化客户端
    for (int i = 0; i < IP_POOL_SIZE; i++)
    {
        client_pipes[i][0] = -1;
        client_pipes[i][1] = -1;
    }

    // 初始化客户端锁
    if (pthread_mutex_init(&client_lock, NULL) != 0) {
        perror("Mutex init failed");
        return -1;
    }

    // 初始化ip池
    if (init_ip_pool(&ip_pool, ip_cidr) != 0)
    {
        fprintf(stderr, "Failed init ip pool: %s\n", ip_cidr);
        return -1;
    }

    // 保留客户端ip
    if (reserve_user_ip(&ip_pool) != 0)
    {
        fprintf(stderr, "Failed reserver user ip.\n");
        return -1;
    }

    // 分配服务器ip
    if (get_next_available_ip(&ip_pool, ip, sizeof(ip)) == 0) {
        logger("Allocated IP: %s\n", ip);
    } else {
        fprintf(stderr, "No available IP addresses\n");
        return -1;
    }

    // 创建tun设备
    tun_fd = createVPNtun(ip);

    // 开启线程处理tun数据
    pthread_t thread;
    if (pthread_create(&thread, NULL, vpnServerTunThread, NULL) != 0) {
        fprintf(stderr, "Thread creation failed");
        close(tun_fd);
        return -1;
    }

    return tun_fd;
}

// 子进程tun函数
void vpnServerClientMain(SSL *ssl, int pipe_fd)
{
    char buf[TUN_BUF_SIZE];
    int sock_fd = SSL_get_fd(ssl);
    while (1)
    {
        int len;

        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(sock_fd, &readFDSet);
        FD_SET(pipe_fd, &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(sock_fd, &readFDSet)) {
            // 客户端发给服务端数据 转发到tun设备
            len = SSL_read(ssl, buf, sizeof(buf));
            if (len <= 0)
            {
                if (len < 0)
                {
                    fprintf(stderr, "SSL_read() failed: (%d) %s\n", errno, strerror(errno));
                    continue;
                }
                break;
            }
            DBG_DUMP_SIMPLE("ssl->tun", buf, len);
            len = write(tun_fd, buf, len);
            if (len < 0)
            {
                fprintf(stderr, "tun_fd write() failed: (%d) %s\n", errno, strerror(errno));
                break;
            }
        }
        else if (FD_ISSET(pipe_fd, &readFDSet))
        {
            // 服务器发送给客户端数据 转发到ssl
            // 先读取管道中数据长度
            read(pipe_fd, &len, sizeof(len));
            // 再读取管道中数据
            len = read(pipe_fd, buf, len);
            if (len < 0)
            {
                fprintf(stderr, "pipe_fd read() failed: (%d) %s\n", errno, strerror(errno));
            }
            DBG_DUMP_SIMPLE("tun->ssl", buf, len);
            len = SSL_write(ssl, buf, len);
            if (len < 0)
            {
                fprintf(stderr, "SSL_write() failed: (%d) %s\n", errno, strerror(errno));
            }
        }
    }
}

// 父进程tun线程
void *vpnServerTunThread(void *null_arg) {
    char buf[TUN_BUF_SIZE];
    while (1)
    {
        int len;

        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(tun_fd, &readFDSet);
        FD_SET(global_client_pipe[0], &readFDSet);
        select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(tun_fd, &readFDSet)) {
            bzero(buf, sizeof(buf));
            len = read(tun_fd, buf, sizeof(buf));
            if (len < 0) {
                fprintf(stderr, "tun_fd read() failed: (%d) %s\n", errno, strerror(errno));
                break;
            }
            // char ip_src[INET_ADDRSTRLEN];
            // char ip_dst[INET_ADDRSTRLEN];
            // struct in_addr addr;
            // src
            // addr.s_addr = *(int *)(buf+12);
            // inet_ntop(AF_INET, &addr, ip_src, INET_ADDRSTRLEN);
            // dst
            // addr.s_addr = *(int *)(buf+16);
            // inet_ntop(AF_INET, &addr, ip_dst, INET_ADDRSTRLEN);
            // printf("src: %s\ndst: %s\n", ip_src, ip_dst);
            // int index = get_ip_index(&ip_pool, ip_dst);
            int addr = *(int *)(buf+16);
            int index = -1;
            if ((addr & ip_pool.mask) == (ip_pool.base_ip & ip_pool.mask)) {
                index = ntohl(addr) - ntohl(ip_pool.base_ip & ip_pool.mask);
            }

            if (index < 0 || index >= IP_POOL_SIZE)
            {
                // 错误大小的ip包，跳过
                continue;
            }
            int pipe_fd = client_pipes[index][1];
            if (pipe_fd < 0)
            {
                // 客户端对端不存在
                continue;
            }
            // 第一次先将数据长度写入
            write(pipe_fd, &len, sizeof(len));
            // 第二次写入真实数据
            len = write(pipe_fd, buf, len);
            if (len < 0)
            {
                fprintf(stderr, "pipe_fd write() failed: (%d) %s\n", errno, strerror(errno));
            }
        }
        else if (FD_ISSET(global_client_pipe[0], &readFDSet))
        {
            // 客户端离线消息
            char off_msg[32];
            len = read(global_client_pipe[0], off_msg, sizeof(off_msg));
            if (len < 0)
            {
                fprintf(stderr, "pipe_fd read() failed: (%d) %s\n", errno, strerror(errno));
            }
            int index = -1;
            sscanf(off_msg, "client [%d] offline", &index);
            if (index < 0)
            {
                continue;
            }
            pthread_mutex_lock(&client_lock);
            // 回收ip
            if (ip_pool.status[index] == USED)
            {
                ip_pool.status[index] = AVAILABLE;
            }
            // 关闭管道
            close(client_pipes[index][1]);
            client_pipes[index][0] = -1;
            client_pipes[index][1] = -1;
            pthread_mutex_unlock(&client_lock);
            char ip_str[INET_ADDRSTRLEN];
            struct in_addr addr;
            addr.s_addr = htonl(ntohl(ip_pool.base_ip) + index);
            inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
            logger("Client %s offline\n", ip_str);
        }
    }
    return NULL;
}

// 新的客户端连接
void *newVPNClient(void *ssl_arg)
{
    SSL *ssl = (SSL *)ssl_arg;
    int sock = SSL_get_fd(ssl);

    char user_buf[USER_BUF_LEN];
    char user_record[USER_RECORD_LEN];
    memset(user_buf, '\0', sizeof(user_buf));
    memset(user_record, '\0', sizeof(user_record));

    int client_pipe[2];
    int tmp_pipe[2];
    pipe(client_pipe);
    pipe(tmp_pipe);
    if (fork() == 0) { // The child process
        close(client_pipe[1]);
        close(tmp_pipe[0]);
        close(global_client_pipe[0]);
        close(listen_sock);

        SSL_accept(ssl);

        // 用户登陆
        SSL_read(ssl, user_buf, sizeof(user_buf));
        write(tmp_pipe[1], user_buf, sizeof(user_buf));
        close(tmp_pipe[1]);
        read(client_pipe[0], user_record, sizeof(user_record));

        if (strlen(user_record) != 0)
        {
            SSL_write(ssl, user_record, strlen(user_record));
            vpnServerClientMain(ssl, client_pipe[0]);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        
        // 子进程退出 向父进程管道发送退出
        char off_msg[32];
        char *ch = strchr(user_record, ':');
        *ch = '\0';
        int index = get_ip_index(&ip_pool, user_record);
        snprintf(off_msg, sizeof(off_msg), "client [%d] offline", index);
        write(global_client_pipe[1], off_msg, sizeof(off_msg));
        exit(0);
    } else {
        SSL_free(ssl);
        close(sock);
        close(client_pipe[0]);
        close(tmp_pipe[1]);

        //  处理用户登陆
        int ret = read(tmp_pipe[0], user_buf, sizeof(user_buf));
        close(tmp_pipe[0]);
        if (ret == 0)
        {
            logger("Login failed, SSL closed\n");
            return NULL;
        }
        if (check_user(user_buf, user_record, sizeof(user_record)) != 0)
        {
            // 登陆失败 关闭连接
            write(client_pipe[1], user_record, sizeof(user_record));
            logger("Login failed, SSL closed\n");
            return NULL;
        }

        char user_name[USER_NAME_LEN+1];
        char ip[IP_LEN];
        char network[NETWORK_LEN];
        char *token0 = strchr(user_record, ':');
        *token0 = '\0';
        token0++;
        char *token1 = strchr(token0, ':');
        *token1 = '\0';
        token1++;
        char *token2 = strchr(token1, ':');
        *token2 = '\0';
        token2++;
        strncpy(user_name, user_record, sizeof(user_name));
        strncpy(ip, token1, sizeof(ip));
        strncpy(network, token2, sizeof(network));

        pthread_mutex_lock(&client_lock);

        if (strlen(ip) == 0)
        {
            get_next_available_ip(&ip_pool, ip, sizeof(ip));
        }
        if (strlen(network) == 0)
        {
            strncpy(network, default_network, sizeof(network));
        }
        int index = get_ip_index(&ip_pool, ip);
        if (client_pipes[index][0] != -1 || client_pipes[index][1] != -1)
        {
            // 已存在的连接 登陆失败
            write(client_pipe[1], user_record, sizeof(user_record));
            logger("Client %s already login, SSL closed\n", user_name);
            pthread_mutex_unlock(&client_lock);
            return NULL;
        }
        client_pipes[index][0] = client_pipe[0];
        client_pipes[index][1] = client_pipe[1];

        pthread_mutex_unlock(&client_lock);

        memset(user_record, '\0', sizeof(user_record));
        snprintf(user_record, sizeof(user_record), "%s:%s", ip, network);
        write(client_pipe[1], user_record, sizeof(user_record));
        logger("New clinet: [%s:%s:%s]\n", user_name, ip, network);
    }
    return NULL;
}
