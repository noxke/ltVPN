// 配置信息

#define DEFAULT_CONFIG_PATH1 "./configs"
#define DEFAULT_CONFIG_PATH2 "/etc/ltvpn"

#define SERVER_CONF "server.conf"
#define CLIENT_CONF "client.conf"

#define MIN_PATH 160
#define MAX_PATH 200

#define MAX_PASSWD_LEN 64

extern char config_path[MIN_PATH];
extern char ca_cert[MAX_PATH];
extern char server_cert[MAX_PATH];
extern char server_key[MAX_PATH];
extern char server_passwd[MAX_PASSWD_LEN];

extern char server_host[MIN_PATH];
extern int server_port;

extern char ip_cidr[MIN_PATH];
extern char default_network[MAX_PATH];

extern char user_list_path[MAX_PATH];

extern char default_username[MAX_PASSWD_LEN];
extern char default_userpasswd[MAX_PASSWD_LEN];

// 服务端运行模式
#define SERVER_RUN 0
#define ADD_USER 1
extern int server_mode;

// 解析配置文件
int parser_config(const char *fconf);
