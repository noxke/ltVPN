#define USER_NAME_LEN 15
#define USER_PASSWD_LEN 64
#define USER_BUF_LEN 64
#define IP_LEN 32
#define NETWORK_LEN 128
#define USER_RECORD_LEN 256

// 用户名密码输入 错误返回非0
int input_user(char *buf, size_t size);
// 新增用户
int new_user();
// 从用户列表中查找用户名 未找到返回非0
int find_user(char *user_name, char *buf, size_t size);
// 检查用户及密码 失败返回非0
int check_user(char *user, char *buf, size_t size);