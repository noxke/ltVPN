FROM ubuntu:22.04

ENV LANG='en_US.UTF-8' \
    LANGUAGE='en_US:en' \
    LC_ALL='en_US.UTF-8' \
    USER=root \
    PASSWD=passwd

# 换源
RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list
RUN sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list

# 安装ssh服务
RUN apt-get update \
    && apt-get install -y openssh-server \
    && echo "PermitRootLogin yes" >>  /etc/ssh/sshd_config \
    && echo "port 22" >> /etc/ssh/sshd_config \
    && /etc/init.d/ssh start

# 安装常用工具
RUN apt-get install -y \
    screen vim curl zip unzip wget htop net-tools inetutils-ping

# 安装telnet openssl
RUN apt-get install -y \
    libssl-dev telnetd telnet

# 清除apt缓存
RUN apt-get autoclean && rm -rf /var/lib/apt/lists/*

# 修改root用户密码
RUN echo "$USER:$PASSWD" | chpasswd

# bashrc
RUN cp /etc/skel/.bash_logout /root/ \
    && cp /etc/skel/.bashrc /root/ \
    && cp /etc/skel/.profile /root/

# 创建容器启动时的脚本，脚本内容包括服务的开启，其中tail -f /dev/null为阻塞命令，保证容器运行时不会执行完毕并直接退出
RUN touch start.sh \
    && echo "#!/bin/bash" >> start.sh \
    && echo "" >> start.sh \
    && echo "/etc/init.d/ssh start" >> start.sh \
    && echo "/etc/init.d/openbsd-inetd start" >> start.sh \
    && echo "tail -f /dev/null" >> start.sh \
    && chmod 777 start.sh

EXPOSE 22

# 启动脚本start.sh
CMD ["./start.sh"]
