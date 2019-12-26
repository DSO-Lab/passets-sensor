## 项目简述

基于pyshark、tshark、pcap、pf_ring实现实时流量分析，使用syslog方式输出TCP及HTTP两种资产数据。

## main.py参数说明

```
-i  流量采集网卡（例如：eth0、ens192），需必填
-s  syslog服务器地址，需必填
-p  syslog服务器监听端口，需必填
-t  标识流量来源，Default:localhost
-r  深度资产信息采集开关，off|on，Default:on
-d  Debug调试信息开关，off|on，Default:off
-c  缓存大小，用于过滤瞬时重复数据，Default:1024
-S  流量会话缓存大小，用于重组通讯会话，Default:1024
-T  定期重启清空内存，Default:3600
```

## Dockerfile构建

```
docker build -t dsolab/passets-sensor:<tag> .
```

### docker-compose运行

```
# 启动
docker-compose up -d
# 停止
docker-compose down
```

docker-compose.yml配置文件说明：

```
version: "3"

services:
  passets-sensor:
    build:
      context: ./
    image: dsolab/passets-sensor:<tag>
    container_name: passets-sensor
    environment:
      # 量采集网卡（例如：eth0、ens192），需必填
      - interface=<ens192>
      # syslog服务器地址，需必填
      - ip=SyslogIP
      # syslog服务器监听端口，需必填
      - port=SyslogPort
      # 标识流量来源，Default:localhost
      - tag=localhost
      # 深度资产信息采集开关，off|on，Default:on
      - switch=on
      # 缓存大小，用于过滤瞬时重复数据，Default:1024
      - cache=1024
      # 定期重启清空内存，Default:3600
      - timeout=3600
      # Debug调试信息开关，off|on，Default:off
      - debug=off
      # 非必填，根据http请求状态码过滤
      - http_filter_code=400,404,304
      # 非必填，根据http页面类型过滤
      - http_filter_type=audio/,video/,image/
    network_mode: host
    restart: unless-stopped
```

## CMD运行

```
docker run --restart=unless-stopped -d -e tag="localhost" -e interface="ens192" -e ip="SyslogIP" -e port="SyslogPort" -e switch="on" -e debug="off" -e cache="1024" -e timeout="3600" --net=host -it doslab/passets-sensor:<tag> /bin/bash
```

## 输出数据格式

HTTP OUTPUT JSON

```
{
  # URL
  "url": "http://www.dsolab.org/",    
  # 协议（HTTP/HTTPS）
  "pro": "HTTP",
  # 来源标识
  "tag": "dsolab",      
  # 服务IP 
  "ip": "108.x.x.136",    
  # 服务端口
  "port": "80",   
  # 网站响应状态码
  "code": "200",    
  # 网站页面类型
  "type": "text/html",        
  # 网站server头信息
  "server": "nginx/1.16.1", 
  # 网站响应body信息（仅-r on时返回）
  "body": "<html>...</html>"                    
}
```

TCP OUTPUT JSON

```
{
  # 协议
  "pro": "TCP",      
  # 来源标识
  "tag": "dsolab",    
  # 服务IP
  "ip": "192.x.x.53", 
  # 服务端口
  "port": "3306",     
  # TCP第一个响应报文（仅-r on时返回）
  "data": "590000000a352e352e352d31302e312e32342d4d61726961444200a601000061655662665b776200fff72102003fa015000000000000000000006451474f396b345e5f40614a006d7973716c5f6e61746976655f70617373776f726400"                                     
}
```

## FAQ

Q: 为什么无法捕获网口流量？

> 首先确认网口流量镜像配置正确，然后要确认网络工作模式（network_mode）是host。

Q: 深度资产信息采集，有哪些用途？

> 当-r on时，开启深度资产信息采集，会采集HTTP页面html数据和TCP第一个响应报文数据，数据可以用于协议识别、web应用指纹识别，如识别。但是，采集压力会上升，性能会下降。

Q：采用了哪种缓存机制？

> 本模块采用 LRU (最近最少使用)机制来进行数据缓存处理，以降低 logstash 的处理压力。HTTP协议、TCP协议（含HTTPS）分别独享用户定义的缓存空间。

Q：LRU算法的设计原则是什么？

> 如果一个数据在最近一段时间没有被访问到，那么在将来它被访问的可能性也很小。也就是说，当限定的空间已存满数据时，应当把最久没有被访问到的数据淘汰。

**深度资产信息采集**

只有开启了深度资产信息采集开关，才可以采集到 HTTP 响应头、HTTP响应正文、TCP响应报文和HTTPS站点。

**协议支持**

- HTTP

- HTTPS

- TCP

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

