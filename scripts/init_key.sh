#!/bin/bash

# 配置文件目录
if [ -n "$1" ]; then
    CONFIG_DIR="$1"
else
    if [ -d "/etc/ltvpn" ]; then
        CONFIG_DIR="/etc/ltvpn"
    else
        CONFIG_DIR="./configs"
    fi
fi

CONFIG_DIR="${CONFIG_DIR%/}"

# ltvpn配置文件
source "$CONFIG_DIR/key.conf"

# openssl配置文件
OPENSSL_CNF="$CONFIG_DIR/openssl.conf"

# 清除存在的证书和签名
if [ -f "$CONFIG_DIR/ca.crt" ]; then
    rm -f "$CONFIG_DIR/ca.crt"
fi
if [ -f "$CONFIG_DIR/ca.key" ]; then
    rm -f "$CONFIG_DIR/ca.key"
fi
if [ -f "$CONFIG_DIR/server.crt" ]; then
    rm -f "$CONFIG_DIR/server.crt"
fi
if [ -f "$CONFIG_DIR/server.key" ]; then
    rm -f "$CONFIG_DIR/server.key"
fi
if [ -f "$CONFIG_DIR/server.csr" ]; then
    rm -f "$CONFIG_DIR/server.csr"
fi

# CA目录
if [ -d "$CONFIG_DIR/demoCA" ]; then
    rm -rf "$CONFIG_DIR/demoCA"
fi

mkdir "$CONFIG_DIR/demoCA"
mkdir "$CONFIG_DIR/demoCA/newcerts"
touch "$CONFIG_DIR/demoCA/index.txt"
echo 1000 > "$CONFIG_DIR/demoCA/serial"

# 生成CA
CONFIG_DIR="$CONFIG_DIR" \
REQ_PASSWD="$CA_PASSWD" \
commonName="$CA_commonName" \
countryName="$CA_countryName" \
stateOrProvinceName="$CA_stateOrProvinceName" \
organizationName="$CA_organizationName" \
organizationalUnitName="$CA_organizationalUnitName" \
emailAddress="$CA_emailAddress" \
challengePassword="$challengePassword" \
unstructuredName="$unstructuredName" \
openssl req -new -x509 \
    -keyout "$CONFIG_DIR/ca.key" \
    -out "$CONFIG_DIR/ca.crt" \
    -config "$OPENSSL_CNF"

# 生成服务器密钥
openssl genrsa -des3 \
    -out "$CONFIG_DIR/server.key" \
    -passout pass:"$SERVER_PASSWD" \
    2048 

# 生成签名请求
CONFIG_DIR="$CONFIG_DIR" \
REQ_PASSWD="$CA_PASSWD" \
commonName="$SERVER_commonName" \
countryName="$SERVER_countryName" \
stateOrProvinceName="$SERVER_stateOrProvinceName" \
organizationName="$SERVER_organizationName" \
organizationalUnitName="$SERVER_organizationalUnitName" \
emailAddress="$SERVER_emailAddress" \
challengePassword="$challengePassword" \
unstructuredName="$unstructuredName" \
openssl req -new \
    -key "$CONFIG_DIR/server.key" \
    -out "$CONFIG_DIR/server.csr" \
    -config "$OPENSSL_CNF"

# 证书签名
CONFIG_DIR="$CONFIG_DIR" \
REQ_PASSWD="$CA_PASSWD" \
commonName="$SERVER_commonName" \
countryName="$SERVER_countryName" \
stateOrProvinceName="$SERVER_stateOrProvinceName" \
organizationName="$SERVER_organizationName" \
organizationalUnitName="$SERVER_organizationalUnitName" \
emailAddress="$SERVER_emailAddress" \
challengePassword="$challengePassword" \
unstructuredName="$unstructuredName" \
openssl ca \
    -in "$CONFIG_DIR/server.csr" \
    -out "$CONFIG_DIR/server.crt" \
    -cert "$CONFIG_DIR/ca.crt" \
    -keyfile "$CONFIG_DIR/ca.key" \
    -passin pass:"$CA_PASSWD" \
    -config "$OPENSSL_CNF" \
    -batch
