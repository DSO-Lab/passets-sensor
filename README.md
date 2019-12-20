### 项目简述

基于pyshark、tshark、pcap、pf_ring实现实时流量分析，使用syslog方式输出TCP及HTTP两种资产数据。

### main.py参数说明

```
-i  流量采集网卡（例如：eth0、ens192），需必填
-s  syslog服务器地址，需必填
-p  syslog服务器监听端口，需必填
-t  标识流量来源，Default:localhost
-r  深度资产信息采集开关，off|on，Default:on
-d  Debug调试信息开关，off|on，Default:off
-c  缓存大小，用于过滤瞬时重复数据，Default:1024
-T  定期重启清空内存，Default:3600
```

### Dockerfile构建

```
docker build -t passets-sensor:<tag> .
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
      - interface=<ens192>			# 量采集网卡（例如：eth0、ens192），需必填
      - ip=SyslogIP				# syslog服务器地址，需必填
      - port=SyslogPort				# syslog服务器监听端口，需必填
      - tag=localhost				# 标识流量来源，Default:localhost
      - switch=on				# 深度资产信息采集开关，off|on，Default:on
      - cache=1024				# 缓存大小，用于过滤瞬时重复数据，Default:1024
      - timeout=3600				# 定期重启清空内存，Default:3600
      - debug=off				# Debug调试信息开关，off|on，Default:off
    network_mode: host
    restart: unless-stopped
```

### CMD运行

```
docker run --restart=unless-stopped -d -e tag="localhost" -e interface="ens192" -e ip="SyslogIP" -e port="SyslogPort" -e switch="on" -e debug="off" -e cache="1024" -e timeout="3600" --net=host -it doslab/passets-sensor:<tag> /bin/bash
```

### 输出数据格式

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

### FAQ

Q: 为什么无法捕获网口流量？

> 首先确认网口流量镜像配置正确，然后要确认网络工作模式（network_mode）是host。

Q: 深度资产信息采集，有哪些用途？

> 当-r on时，开启深度资产信息采集，会采集HTTP页面html数据和TCP第一个响应报文数据，数据可以用于协议识别、web应用指纹识别。但是，采集压力会上升，性能会下降。

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

