#-*- coding:utf-8 -*-

from lib._http_tcp_shark import tcp_http_sniff
from lib._logging import check_lock
import getopt
import sys

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
# 数据是否在console显示
display_switch = False
# 开启深度数据分析
return_deep_info = False
# 缓存数量
cache_size = 512
# 最大运行时间，重启清空内存
timeout = 3600
# debug模式
debug = False
# 数据过滤配置
filter_rules = {
	"content_type":[
		"audio/",
		"video/",
		"image/",
		"font/",
		"application/pdf",
		"application/msword",
		"application/javascript",
		"text/javascript",
		"text/css"],
	"response_code":[
		'400', '404', '301', '302', '304'
	]
}

def Usage():
	print('''
 ########################################################################
 #                         passets-sensor 1.0.1                         #
 ########################################################################
 ------------------------------------------------------------------------
 Usage:
 python3 main.py -i [interface] -t [tag] -s [syslog_ip] -p [syslog_port]
 ------------------------------------------------------------------------
	''')
	sys.exit()

def main():
	sniff_obj = tcp_http_sniff(interface, display_filter, syslog_ip, syslog_port, display_switch, custom_tag, return_deep_info, filter_rules, cache_size, bpf_filter, timeout, debug)
	sniff_obj.run()

if __name__ == '__main__':

	# crontab方式启动
	# */5 * * * * root /usr/bin/python3 /passets-sensor/main.py >> /dev/null 2>&1
	# check_lock()

	try:
		opts,args = getopt.getopt(sys.argv[1:],'i: s: p: d: t: r: n:')
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
			display_str = str(a)
			if display_str == 'on':
				display_switch = True
		if o == '-r':
			return_switch_str = str(a)
			if return_switch_str == 'on':
				return_deep_info = True
		if o == '-n':
			cache_size = int(a)

	if interface and syslog_ip and syslog_port and cache_size:
		try:
			main()
		except KeyboardInterrupt:
			print('\nExit.')
	else:
		Usage()