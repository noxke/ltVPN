#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"

char config_path[MIN_PATH];
char ca_cert[MAX_PATH];
char server_cert[MAX_PATH];
char server_key[MAX_PATH];
char server_passwd[MAX_PASSWD_LEN];

char server_host[MIN_PATH];
int server_port;

char ip_cidr[MIN_PATH];
char default_network[MAX_PATH];

char user_list_path[MAX_PATH];

char default_username[MAX_PASSWD_LEN];
char default_userpasswd[MAX_PASSWD_LEN];

int server_mode = -1;


// 解析配置文件
int parser_config(const char *fconf)
{
    char fconfig[MAX_PATH];
    char line_buf[MAX_PATH];
    FILE *fp;

    memset(ca_cert, '\0', MAX_PATH);
    memset(server_cert, '\0', MAX_PATH);
    memset(server_key, '\0', MAX_PATH);
    memset(server_passwd, '\0', MAX_PASSWD_LEN);
    memset(user_list_path, '\0', MAX_PATH);
    memset(default_username, '\0', MAX_PASSWD_LEN);
    memset(default_userpasswd, '\0', MAX_PASSWD_LEN);

    memset(fconfig, '\0', MAX_PATH);
    snprintf(fconfig, MAX_PATH, "%s/%s", config_path, fconf);
    fp = fopen(fconfig, "rt");
    if (fp == NULL)
    {
        fprintf(stderr, "Open config file %s failed.\n", fconfig);
        return -1;
    }

    for (int line_no = 0;; line_no++)
    {
        char ch = '\0';
        memset(line_buf, '\0', sizeof(line_buf));
        for (int i = 0;; i++)
        {
            ch = fgetc(fp);
            if (ch == EOF || ch == '\n')
            {
                break;
            }
            if (i < sizeof(line_buf))
            {
                line_buf[i] = ch;
            }
            else
            {
                fprintf(stderr, "Line %d invalid(must less than %ld).\n", line_no, sizeof(line_buf));
                return -1;
            }
        }
        // 配置文件结尾
        if (ch == EOF)
        {
            break;
        }
        // 注释行 空行
        if (line_buf[0] == '#' || strlen(line_buf) == 0)
        {
            continue;
        }
        char *peq = strchr(line_buf, '=');
        if (peq == NULL)
        {
            fprintf(stderr, "Line %d invalid: %s\n", line_no, line_buf);
            return -1;
        }
        *peq = '\0';
        if ( peq - line_buf == strlen("cacert") && strcmp(line_buf, "cacert") == 0)
        {
            // CA证书
            snprintf(ca_cert, sizeof(ca_cert), "%s/%s", config_path, peq+1);
        }
        else if ( peq - line_buf == strlen("cert") && strcmp(line_buf, "cert") == 0)
        {
            // 服务器证书
            snprintf(server_cert, sizeof(server_cert), "%s/%s", config_path, peq+1);
        }
        else if ( peq - line_buf == strlen("key") && strcmp(line_buf, "key") == 0)
        {
            // 服务器私钥
            snprintf(server_key, sizeof(server_key), "%s/%s", config_path, peq+1);
        }
        else if ( peq - line_buf == strlen("user_list") && strcmp(line_buf, "user_list") == 0)
        {
            // 用户列表
            snprintf(user_list_path, sizeof(user_list_path), "%s/%s", config_path, peq+1);
        }
        else if ( peq - line_buf == strlen("key_passwd") && strcmp(line_buf, "key_passwd") == 0)
        {
            // 私钥口令
            snprintf(server_passwd, sizeof(server_passwd), "%s", peq+1);
        }
        else if ( peq - line_buf == strlen("server") && strcmp(line_buf, "server") == 0)
        {
            // 服务器地址
            snprintf(server_host, sizeof(server_host), "%s", peq+1);
        }
        else if ( peq - line_buf == strlen("port") && strcmp(line_buf, "port") == 0)
        {
            // 服务器端口
            server_port = atoi(peq+1);
            if (server_port == 0)
            {
                *peq = '=';
                fprintf(stderr, "Line %d invalid: %s\n", line_no, line_buf);
                return -1;
            }
        }
        else if ( peq - line_buf == strlen("ip_cidr") && strcmp(line_buf, "ip_cidr") == 0)
        {
            // VPN网络
            snprintf(ip_cidr, sizeof(ip_cidr), "%s", peq+1);
        }
        else if ( peq - line_buf == strlen("network") && strcmp(line_buf, "network") == 0)
        {
            // 路由网络
            snprintf(default_network, sizeof(default_network), "%s", peq+1);
        }
        else if ( peq - line_buf == strlen("user") && strcmp(line_buf, "user") == 0)
        {
            // 客户端默认用户名
            snprintf(default_username, sizeof(default_username), "%s", peq+1);
        }
        else if ( peq - line_buf == strlen("passwd") && strcmp(line_buf, "passwd") == 0)
        {
            // 客户端默认密码
            snprintf(default_userpasswd, sizeof(default_userpasswd), "%s", peq+1);
        }
        else
        {
            // 未找到匹配的配置项目
            *peq = '=';
            fprintf(stderr, "Line %d invalid: %s\n", line_no, line_buf);
            return -1;
        }
    }
    return 0;
}