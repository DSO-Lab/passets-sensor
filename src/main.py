#-*- coding:utf-8 -*-

from lib._http_tcp_shark import tcp_http_sniff
from lib._logging import check_lock
import getopt
import sys
import os
import json

# syslog服务器地址和端口信息
syslog_ip = '127.0.0.1'
syslog_port = 514
# 监听网卡
interface = 'eth0'
# 主机标识
custom_tag = '127.0.0.1'
# bpf_filter
bpf_filter = 'tcp'
# display_filter
display_filter = "tcp.flags.reset == 0"
# debug模式，数据console输出
debug = False
# 开启深度数据分析
return_deep_info = True
# 缓存数量
cache_size = 1024
# 定时清空内存
timeout = 3600
# HTTP数据过滤
http_filter_code_list = list(set(filter(None, os.environ["http_filter_code"].replace(" ","").split(","))))
http_filter_type_list = list(set(filter(None, os.environ["http_filter_type"].replace(" ","").split(","))))
http_filter_json = {"response_code":http_filter_code_list,"content_type":http_filter_type_list}

def Usage():
	print('''
 ###################################################################
 #                      passets-sensor 1.0.0                       #
 ###################################################################
 -------------------------------------------------------------------
 Usage:
 python3 main.py [options] ...

 -i <interface>     Name or idx of interface(def: None)		 
 -s <syslog_ip>     Syslog server ip(def: None)
 -p <syslog_port>   Syslog server port(def: None)
 -t <tag>           Source identification(def: localhost)
 -c <cache_size>    Cache size(def: 1024)
 -T <timeout>       Memory clear time(def: 3600 sec)
 -r <off|on>        Depth information switch(def: on)
 -d <off|on>        Debug information switch(def: off)
 -------------------------------------------------------------------
	''')
	sys.exit()

def main():
	sniff_obj = tcp_http_sniff(interface, display_filter, syslog_ip, syslog_port, custom_tag, return_deep_info, http_filter_json, cache_size, bpf_filter, timeout, debug)
	sniff_obj.run()

if __name__ == '__main__':

	# crontab方式启动
	# */5 * * * * root /usr/bin/python3 /passets-sensor/main.py >> /dev/null 2>&1
	# check_lock()

	try:
		opts,args = getopt.getopt(sys.argv[1:],'i: s: p: d: t: r: c: T:')
	except:
		Usage()
	if len(opts) < 4:
		Usage()

	for o, a in opts:
		if o == "-i":
			interface = str(a)
		if o == '-s':
			syslog_ip = str(a)
		if o == '-t':
			custom_tag = str(a)
		if o == '-p': 
			syslog_port = int(a)
		if o == '-d':
			debug_str = str(a)
			if debug_str == 'on':
				debug = True
		if o == '-r':
			return_switch_str = str(a)
			if return_switch_str == 'on':
				return_deep_info = True
		if o == '-c':
			cache_size = int(a)
		if o == '-T':
			timeout = int(a)
	if interface and syslog_ip and syslog_port and cache_size:
		try:
			main()
		except KeyboardInterrupt:
			print('\nExit.')
	else:
		Usage()