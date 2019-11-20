###主要代码说明

main.py 参数说明：

```
-i  指定捕获流量的网卡接口，例如：eth0、ens192
-t  发送的Syslog打的标签，用于标识流量来源
-s  Syslog服务器地址
-p  Syslog服务器监听端口
-r  是否收集HTTP响应头和正文的开关，off|on
-d  是否在Stdout打印数据的开关，off|on
```

###基础镜像配置

Dockerfile image生成

```
#FROM harbor.shuziguanxing.com/pad/passets:1.0.0
FROM docker.io/ubuntu:18.04

MAINTAINER rH.5@shuziguanxing

COPY src /root/passets

RUN apt-get update 
RUN sh -c "/bin/echo -e yes\n"|apt-get -y install tshark && \
	apt-get -y install python3 python3-pip python3-lxml && \
	pip3 install cacheout && \
	pip3 install pyshark && \
	chmod 750 /usr/bin/dumpcap && \
	chgrp root /usr/bin/dumpcap && \
	apt-get clean && \
	apt-get autoclean && \
	apt-get autoremove


ENTRYPOINT ["/bin/bash","-c","/usr/bin/python3 /root/passets/main.py -i $interface -t $tag -s $ip -p $port -r $switch -d $debug"]
```

最终Images Build过程

```
docker build -t passets:1.0.0 .
或
docker-compose up
docker-compose build
```

最终images导出和导入

```
docker commit <CONTAINER ID> passets:1.0.0

docker export eb16cbc77af0 > /home/passets-x86_64.tar
cat /home/passets-x86_64.tar | docker import - passets:1.0.0
```

###容器启动

docker-compose启动容器

```
version: "3"

services:
  passets:
    build:
      context: ./
    image: passets:1.0.0
    container_name: passets
    environment:
      - tag=localhost
      - interface=ens192
      - ip=192.168.199.132
      - port=5044
      - switch=on
      - debug=off
    network_mode: host
    restart: always
```

命令行创建并启动容器

```
docker run --restart=unless-stopped -d -e tag="localhost" -e interface="ens192" -e ip="192.168.199.132" -e port="5044" -e switch="on" -e debug="off" --net=host -v /tmp:/mnt -it passets:1.0.0 /bin/bash
```

### FAQ

Q: 为什么使用docker-compose 启动镜像后无法捕获网口流量？

> 首先确认网口配置正确，然后要确认网络工作模式（network_mode）是host。
