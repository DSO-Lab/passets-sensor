### 项目简述

基于pyshark、tshark、pf_ring实现实时流量分析，使用syslog方式输出TCP及HTTP两种json格式数据。

### 参数说明

```
-i  捕获流量的网卡接口，例如：eth0、ens192
-t  发送的Syslog打标签，用于标识流量来源
-s  Syslog服务器地址
-p  Syslog服务器监听端口
-r  是否收集HTTP响应头和正文的开关，off|on
-d  是否在Stdout打印数据的开关，off|on
```

### Dockerfile

```
FROM docker.io/ubuntu:18.04

COPY src /root/passets-sensor

RUN	apt-get -y update && \
	apt-get -y install software-properties-common wget && \
	wget -q http://apt-stable.ntop.org/18.04/all/apt-ntop-stable.deb && \
	dpkg -i apt-ntop-stable.deb && \
	apt-get clean all && \
	apt-get -y update && \
	apt-get -y install pfring && \
	DEBIAN_FRONTEND="noninteractive" apt-get -y install tshark && \
	apt-get -y install python3 python3-pip python3-lxml && \
	pip3 install cacheout && \
	pip3 install pyshark && \
	chmod 750 /usr/bin/dumpcap && \
	chgrp root /usr/bin/dumpcap && \
	apt-get autoclean

ENTRYPOINT ["/bin/bash","-c","/usr/bin/python3 /root/passets-sensor/main.py -i $interface -t $tag -s $ip -p $port -r $switch -d $debug"]
```

镜像构建：

```
docker build -t passets-sensor:<tag> .
```

### docker-compose

```
version: "3"

services:
  passets-sensor:
    build:
      context: ./
    image: passets-sensor:<tag>
    container_name: passets-sensor
    environment:
      - tag=localhost
      - interface=ens192
      - ip=SyslogIP
      - port=SyslogPort
      - switch=on
      - debug=off
    network_mode: host
    restart: unless-stopped
```

### 命令行方式启动

```
docker run --restart=unless-stopped -d -e tag="localhost" -e interface="ens192" -e ip="SyslogIP" -e port="SyslogPort" -e switch="on" -e debug="off" --net=host -v /tmp:/mnt -it passets-sensor:<tag> /bin/bash
```

### FAQ

Q: 为什么无法捕获网口流量？

> 首先确认网口流量镜像配置正确，然后要确认网络工作模式（network_mode）是host。

Q：是否一定需要安装pf_ring？

> 不需要

Q：安装pf_ring会有哪些提升？

> pf_ring可以减少CPU处理从而提升数据采集能力，官方介绍文档：
>
> <https://www.ntop.org/products/packet-capture/pf_ring/>

Q：如何安装配置pf_ring？

> pf_ring需要在宿主机上进行安装配置，参考文档：
>
>  https://github.com/DSO-Lab/passets/blob/master/docs/PF_RING_Install.md 
>
> 测试pf_ring是否配置成功：
>
> pfcount -i ens192

