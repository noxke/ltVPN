#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>

#include "user.h"
#include "config.h"
#include "logger.h"

/**
* https://github.com/pod32g/MD5
*/

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
void to_bytes(uint32_t val, uint8_t *bytes)
{
    bytes[0] = (uint8_t) val;
    bytes[1] = (uint8_t) (val >> 8);
    bytes[2] = (uint8_t) (val >> 16);
    bytes[3] = (uint8_t) (val >> 24);
}
 
uint32_t to_int32(const uint8_t *bytes)
{
    return (uint32_t) bytes[0]
        | ((uint32_t) bytes[1] << 8)
        | ((uint32_t) bytes[2] << 16)
        | ((uint32_t) bytes[3] << 24);
}
 
void md5(const uint8_t *initial_msg, size_t initial_len, uint8_t *digest) {
 
    // These vars will contain the hash
    uint32_t h0, h1, h2, h3;
 
    // Message (to prepare)
    uint8_t *msg = NULL;
 
    size_t new_len, offset;
    uint32_t w[16];
    uint32_t a, b, c, d, i, f, g, temp;
 
    // Initialize variables - simple count in nibbles:
    h0 = 0x67452301;
    h1 = 0xefcdab89;
    h2 = 0x98badcfe;
    h3 = 0x10325476;
 
    //Pre-processing:
    //append "1" bit to message    
    //append "0" bits until message length in bits ≡ 448 (mod 512)
    //append length mod (2^64) to message
 
    for (new_len = initial_len + 1; new_len % (512/8) != 448/8; new_len++)
        ;
 
    msg = (uint8_t*)malloc(new_len + 8);
    memcpy(msg, initial_msg, initial_len);
    msg[initial_len] = 0x80; // append the "1" bit; most significant bit is "first"
    for (offset = initial_len + 1; offset < new_len; offset++)
        msg[offset] = 0; // append "0" bits
 
    // append the len in bits at the end of the buffer.
    to_bytes(initial_len*8, msg + new_len);
    // initial_len>>29 == initial_len*8>>32, but avoids overflow.
    to_bytes(initial_len>>29, msg + new_len + 4);
 
    // Process the message in successive 512-bit chunks:
    //for each 512-bit chunk of message:
    for(offset=0; offset<new_len; offset += (512/8)) {
 
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        for (i = 0; i < 16; i++)
            w[i] = to_int32(msg + offset + i*4);
 
        // Initialize hash value for this chunk:
        a = h0;
        b = h1;
        c = h2;
        d = h3;
 
        // Main loop:
        for(i = 0; i<64; i++) {
 
            if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }
 
            temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
 
        }
 
        // Add this chunk's hash to result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
 
    }
 
    // cleanup
    free(msg);
 
    //var char digest[16] := h0 append h1 append h2 append h3 //(Output is in little-endian)
    to_bytes(h0, digest);
    to_bytes(h1, digest + 4);
    to_bytes(h2, digest + 8);
    to_bytes(h3, digest + 12);
}

// 检查字符是否为有效用户名字符（大小写字母、数字、下划线）
int is_valid_char(char ch) {
    return isalnum(ch) || ch == '_';
}

// 检查一个字符串是否是有效的IPv4地址
int is_valid_ipv4(const char *ip) {
    int num, dots = 0;
    char *ptr;

    // 如果字符串为空或为NULL
    if (ip == NULL)
        return 0;

    // 复制字符串，因为 strtok 修改字符串
    char *ip_copy = strdup(ip);
    if (ip_copy == NULL)
        return 0;

    ptr = strtok(ip_copy, ".");
    if (ptr == NULL) {
        free(ip_copy);
        return 0;
    }

    while (ptr) {
        // 检查是否是数字
        for (int i = 0; ptr[i] != '\0'; i++) {
            if (!isdigit(ptr[i])) {
                free(ip_copy);
                return 0;
            }
        }

        num = atoi(ptr);

        // 检查数字是否在0到255之间
        if (num < 0 || num > 255) {
            free(ip_copy);
            return 0;
        }

        ptr = strtok(NULL, ".");
        if (ptr != NULL)
            dots++;
    }

    free(ip_copy);

    // 检查是否有三个点
    return dots == 3;
}

// 检查一个字符串是否是有效的CIDR格式
int is_valid_cidr(const char *cidr) {
    char *ip_part, *prefix_part;
    int prefix;

    // 复制字符串，因为 strtok 修改字符串
    char *cidr_copy = strdup(cidr);
    if (cidr_copy == NULL)
        return 0;

    // 拆分字符串为IP部分和前缀部分
    ip_part = strtok(cidr_copy, "/");
    prefix_part = strtok(NULL, "/");

    // 检查IP部分是否有效
    if (!is_valid_ipv4(ip_part)) {
        free(cidr_copy);
        return 0;
    }

    // 检查前缀部分是否是有效数字并且在0到32之间
    if (prefix_part == NULL || !isdigit(*prefix_part) || (prefix = atoi(prefix_part)) < 0 || prefix > 32) {
        free(cidr_copy);
        return 0;
    }

    free(cidr_copy);
    return 1;
}

// 检查包含多个CIDR的字符串，每个CIDR使用逗号隔开
int check_cidr_list(const char *cidr_list) {
    char *cidr, *cidr_list_copy, *saveptr;

    // 复制字符串，因为 strtok 修改字符串
    cidr_list_copy = strdup(cidr_list);
    if (cidr_list_copy == NULL) {
        return 0;
    }

    // 拆分字符串为多个CIDR部分
    cidr = strtok_r(cidr_list_copy, ",", &saveptr);
    while (cidr != NULL) {
        // 去除前后的空格
        while (isspace((unsigned char) *cidr)) cidr++;
        char *end = cidr + strlen(cidr) - 1;
        while (end > cidr && isspace((unsigned char) *end)) end--;
        *(end + 1) = '\0';

        if (!is_valid_cidr(cidr)) {
            return 0;
        }

        cidr = strtok_r(NULL, ",", &saveptr);
    }

    free(cidr_list_copy);
    return 1;
}


int input_user(char *buf, size_t size)
{
    char user_name[USER_NAME_LEN+1];
    char user_passwd[USER_PASSWD_LEN];
    int user_name_len;
    char ch;
    struct termios oldt, newt;
    uint8_t md5_result[16];
    char md5_str[33];

    memset(user_name, 0, sizeof(user_name));
    memset(user_passwd, 0, sizeof(user_passwd));

    if (strlen(default_username) != 0)
    {
        // 使用默认用户名
        strncpy(user_name, default_username, USER_NAME_LEN);
        user_name_len = strlen(default_username);
    }
    else
    {
        printf("Username(up to %d characters):", USER_NAME_LEN);
        for (user_name_len = 0; user_name_len < USER_NAME_LEN; user_name_len++)
        {
            ch = getchar();
            if (ch == '\n' || ch == EOF)
            {
                break;
            }
            user_name[user_name_len] = ch;
        }
        while (ch != '\n' && ch != EOF) ch = getchar();
    }
    if (user_name_len == 0)
    {
        fprintf(stderr, "Invalid empty username.\n");
        return -1;
    }
    // 检查用户名字符
    for (int i = 0; i < user_name_len; i++)
    {
        ch = user_name[i];
        if (!is_valid_char(ch))
        {
            fprintf(stderr, "Invalid character: %c\n.", ch);
            return -1;
        }
    }

    if (strlen(default_userpasswd) != 0)
    {
        // 使用默认密码
        strncpy(user_passwd, default_userpasswd, USER_PASSWD_LEN);
    }
    else
    {
        // 获取终端属性
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;

        // 禁用终端回显
        newt.c_lflag &= ~(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);

        printf("Password(up to %d characters):", USER_PASSWD_LEN);
        for (int i = 0; i < USER_PASSWD_LEN; i++)
        {
            ch = getchar();
            if (ch == '\n' || ch == EOF)
            {
                break;
            }
            user_passwd[i] = ch;
        }
        while (ch != '\n' && ch != EOF) ch = getchar();
        puts("");

        // 还原终端属性
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    }

    // 使用用户名异或密码，加盐
    for (int i = 0; i < USER_PASSWD_LEN; i++)
    {
        user_passwd[i] ^= user_name[i%user_name_len] ^ 0x9E;
    }
    memset(md5_str, '\0', sizeof(md5_str));
    md5((uint8_t *)user_passwd, USER_PASSWD_LEN, md5_result);
    for (int i = 0; i < 16; i++)
        sprintf(md5_str+i*2, "%2.2x", md5_result[i]);
    md5((uint8_t *)md5_str, 32, md5_result);
    for (int i = 0; i < 16; i++)
        sprintf(md5_str+i*2, "%2.2x", md5_result[i]);
    memset(buf, '\0', size);
    snprintf(buf, size, "%s:%s", user_name, md5_str);
    return 0;
}

// 从用户列表中查找用户名 未找到返回0
int find_user(char *user_name, char *buf, size_t size)
{
    FILE *fp;
    char tmp_buf[USER_RECORD_LEN+1];

    fp = fopen(user_list_path, "rt");
    if (fp == NULL)
    {
        return -1;
    }
    while (1)
    {
        memset(tmp_buf, 0, sizeof(tmp_buf));
        int ret = fscanf(fp, "%256s", tmp_buf);
        if(ret == 0 || ret == EOF)
        {
            break;
        }
        char *name_end = strchr(tmp_buf, ':');
        if (name_end != NULL)
        {
            *name_end = '\0';
            if (strcmp(user_name, tmp_buf) == 0)
            {
                if (buf != NULL)
                {
                    *name_end = ':';
                    strncpy(buf, tmp_buf, size);
                }
                fclose(fp);
                return 0;
            }   
        }
    };
    fclose(fp);
    return -1;
}

int new_user()
{
    char user[USER_BUF_LEN];
    char ip[IP_LEN];
    char network[NETWORK_LEN+1];
    char record[USER_RECORD_LEN];

    FILE *fp;
    char ch;

    memset(ip, '\0', sizeof(ip));
    memset(network, '\0', sizeof(network));
    memset(record, '\0', sizeof(record));

    if (input_user(user, USER_BUF_LEN) != 0)
    {
        return -1;
    }
    char *name_end = strchr(user, ':');
    if (name_end == NULL)
    {
        return -1;
    }
    *name_end = '\0';
    if (find_user(user, NULL, 0) == 0)
    {
        fprintf(stderr, "Username already exists.\n");
        return -1;
    }
    *name_end = ':';
    printf("UserIP[CIDR]:");
    for (int i = 0; i < IP_LEN - 1; i++)
    {
        ch = getchar();
        if (ch == '\n' || ch == EOF)
        {
            break;
        }
        ip[i] = ch;
    }
    while (ch != '\n' && ch != EOF) ch = getchar();

    if (strlen(ip) != 0 && !is_valid_cidr(ip))
    {
        fprintf(stderr, "Invalid IP addr.\n");
        return -1;
    }
    printf("Network:");
    for (int i = 0; i < NETWORK_LEN - 1; i++)
    {
        ch = getchar();
        if (ch == '\n' || ch == EOF)
        {
            break;
        }
        network[i] = ch;
    }
    while (ch != '\n' && ch != EOF) ch = getchar();
    if (!check_cidr_list(network))
    {
        fprintf(stderr, "Invalid Network.\n");
        return -1;
    }
    // 将记录写入文件
    snprintf(record, USER_RECORD_LEN, "%s:%s:%s\n", user, ip, network);
    printf("New user record: %s\n", record);
    fp = fopen(user_list_path, "a+");
    if (fp == NULL)
    {
        fprintf(stderr, "Save record to %s failed\n.", user_list_path);
        return -1;
    }
    fputs(record, fp);
    fclose(fp);
    return 0;
}


int check_user(char *user, char *buf, size_t size)
{
    char record[USER_RECORD_LEN];
    char *name_end = strchr(user, ':');
    if (name_end == NULL)
    {
        return -1;
    }
    *name_end = '\0';
    if (find_user(user, record, size) != 0)
    {
        *name_end = ':';
        return -1;
    }
    *name_end = ':';
    if (strncmp(user, record, strlen(user)) != 0)
    {
        return -1;
    }
    if (buf != NULL)
    {
        strncpy(buf, record, size);
    }
    return 0;
}