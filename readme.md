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
FROM docker.io/ubuntu:18.04

COPY src /root/passets-sensor

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


ENTRYPOINT ["/bin/bash","-c","/usr/bin/python3 /root/passets-sensor/main.py -i $interface -t $tag -s $ip -p $port -r $switch -d $debug"]
```

Images Build

```
docker build -t passets-sensor:1.0.0 .
```

###容器启动

docker-compose启动容器

```
version: "3"

services:
  passets-sensor:
    build:
      context: ./
    image: passets-sensor:1.0.0
    container_name: passets-sensor
    environment:
      - tag=localhost
      - interface=ens192
      - ip=localhost
      - port=5044
      - switch=on
      - debug=off
    network_mode: host
    restart: unless-stopped
```

命令行创建并启动容器

```
docker run --restart=unless-stopped -d -e tag="localhost" -e interface="ens192" -e ip="192.168.199.132" -e port="5044" -e switch="on" -e debug="off" --net=host -v /tmp:/mnt -it passets-sensor:1.0.0 /bin/bash
```

### FAQ

Q: 为什么使用docker-compose 启动镜像后无法捕获网口流量？

> 首先确认网口配置正确，然后要确认网络工作模式（network_mode）是host。
