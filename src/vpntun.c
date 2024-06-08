#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>

#include "config.h"
#include "logger.h"
#include "vpntun.h"

#define TUN_DEVICE "/dev/net/tun"
char tun_dev[IFNAMSIZ] = "tun0";

// 创建 TUN 设备
int create_tun_device() {
    struct ifreq ifr;
    int fd, err;

    if ((fd = open(TUN_DEVICE, O_RDWR)) < 0) {
        perror("Opening /dev/net/tun");
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    strncpy(ifr.ifr_name, tun_dev, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return err;
    }

    strcpy(tun_dev, ifr.ifr_name);
    return fd;
}

// 配置 IP 地址和子网掩码
int set_ip_address(const char *cidr) {
    char ip[INET_ADDRSTRLEN];
    int prefix_len;
    struct ifreq ifr;
    struct sockaddr_in *addr;
    int sockfd;

    // 将 CIDR 地址分解为 IP 地址和子网掩码
    char *slash = strchr(cidr, '/');
    if (slash == NULL) {
        fprintf(stderr, "Invalid CIDR format: %s\n", cidr);
        return -1;
    }
    strncpy(ip, cidr, slash - cidr);
    ip[slash - cidr] = '\0';
    prefix_len = atoi(slash + 1);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    addr = (struct sockaddr_in *)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    addr->sin_addr.s_addr = inet_addr(ip);
    strncpy(ifr.ifr_name, tun_dev, IFNAMSIZ-1);

    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(sockfd);
        return -1;
    }

    // 将前缀长度转换为子网掩码
    addr->sin_addr.s_addr = htonl(~((1 << (32 - prefix_len)) - 1));

    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        close(sockfd);
        return -1;
    }

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS)");
        close(sockfd);
        return -1;
    }

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(sockfd);
        return -1;
    }

    close(sockfd);
    return 0;
}


int createVPNtun(const char *ip)
{
    int tun_fd = create_tun_device();
    if (tun_fd < 0) {
        fprintf(stderr, "Failed to create TUN device.\n");
        return tun_fd;
    }
    logger("Created TUN device: %s\n", tun_dev);

    if (set_ip_address(ip) < 0) {
        fprintf(stderr, "Failed to set IP address.\n");
        close(tun_fd);
        return -1;
    }
    logger("Set IP address: %s\n", ip);

    return tun_fd;
}

// 添加路由
int routeAdd(const char *dest_cidr) {
    char command[256];
    snprintf(command, sizeof(command), "route add -net %s dev %s", dest_cidr, tun_dev);
    return system(command);
}
