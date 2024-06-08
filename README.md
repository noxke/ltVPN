# ltVPN

基于TLS的轻量隧道VPN

## build

- 安装编译环境

```bash
apt-get install make gcc openssl libssl-dev
```

- 编译

```bash
make
```

## config

- openssl key配置

```bash
# key.conf

# CA口令
CA_PASSWD="passwd"
# 服务器密钥口令
SERVER_PASSWD="passwd"

# CA证书配置
CA_commonName=ca.example.com
CA_countryName=CN
CA_stateOrProvinceName=example
CA_organizationName=example
CA_organizationalUnitName=example
CA_emailAddress=mail@example.com
# 服务器证书配置
SERVER_commonName=vpn.example.com
SERVER_countryName=CN
SERVER_stateOrProvinceName=example
SERVER_organizationName=example
SERVER_organizationalUnitName=example
SERVER_emailAddress=mail@example.com

challengePassword="challenge_passwd"
unstructuredName=example
```

- 生成openssl key

```bash
./scripts/init_key.sh [configdir]
```

- VPN服务器端配置

```bash
# server.conf

# 服务器证书
cert=server.crt
# 服务器私钥
key=server.key
# 私钥口令
key_passwd=passwd

# 端口
port=8443

# VPN网络
ip_cidr=192.168.11.0/24
# 路由网络 已包含cidr网络
network=192.168.12.0/24

# 用户列表
user_list=user.list
```

- VPN客户端配置

```bash
# client.conf

# CA证书
cacert=ca.crt

# 服务器地址
server=vpn.example.com
# 服务器端口
port=8443

# 用户名
user=user_name
# 密码
passwd=passwd
```

## run

- 设置防火墙转发

```bash
./scripts/openfwd.sh
```

- 添加用户

```bash
./ltvpn-server add_user
```

- VPN服务器端

```bash
./ltvpn-server run

# Usage: ltvpn-server <run/add_user> [options]
# Options:
#   -c <dir>   Specify the configuration directory
#   -d         Run in daemon mode
#   -h         Print this help message and exit
```

- VPN客户端

```bash
./ltvpn-client
# Usage: ltvpn-client [options]
# Options:
#   -c <dir>   Specify the configuration directory
#   -d         Run in daemon mode
#   -h         Print this help message and exit
```