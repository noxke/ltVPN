// 创建tun设备并设置ip
int createVPNtun(const char *ip_cidr);

// 添加路由
int routeAdd(const char *dest_cidr);