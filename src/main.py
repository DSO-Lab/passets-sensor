#-*- coding:utf-8 -*-

from lib._http_tcp_shark import tcp_http_shark
from lib._http_tcp_pcap import tcp_http_pcap
from lib._util import check_lock
from lib._util import _syslog_msg_send, _http_msg_send
import getopt
import sys
import os
import threading
# import queue
import collections
import signal
import traceback

# 数据接收服务器地址和端口信息
server_ip = '127.0.0.1'
server_port = 514
# 监听网卡
interface = 'eth0'
# 主机标识
custom_tag = '127.0.0.1'
# bpf_filter
bpf_filter = 'tcp'
# display_filter
# display_filter = 'tcp'
# debug模式，数据console输出
debug = False
# 开启深度数据分析
return_deep_info = True
# 重复缓存数量
cache_size = 1024
# 流量会话数量
session_size = 1024
# tshark定期清空内存（单位秒/默认一小时），pcap接收数据包的超时时间（单位毫秒/默认3.6秒）
timeout = 3600
# 发送数据线程数量
msg_send_thread_num = 100
# 发送数据队列最大值
max_queue_size = 1000
# 资产数据发送模式，仅支持HTTP，SYSLOG两种
msg_send_mode = 'HTTP'
# 流量采集引擎，仅支持TSHARK，PCAP两种
engine = "PCAP"

# HTTP数据过滤
http_filter = {
	"response_code": ['304', '400', '404'],
	"content_type": [
		'audio/',
		'video/',
		'image/',
		'font/',
		'application/pdf',
		'application/msword',
		'application/javascript',
		'text/javascript',
		'text/css'
	]
}

def Usage():
	print('''
 ###################################################################
 #                      passets-sensor 1.0.0                       #
 ###################################################################
 -------------------------------------------------------------------
 Usage:
 python3 main.py [options] ...

 -i <interface>     Name or idx of interface(def: None)		 
 -s <server_ip>     server ip(def: None)
 -p <server_port>   server port(def: None)
 -t <tag>           Source identification(def: localhost)
 -c <cache_size>    Cache size(def: 1024)
 -S <session_size>  Session size(def: 1024)
 -T <timeout>       Memory clear time(def: 3600 sec)
 -r <off|on>        Depth information switch(def: on)
 -d <off|on>        Debug information switch(def: off)
 -------------------------------------------------------------------
	''')
	sys.exit()

def tshark_analysis(work_queue):

	shark_obj = tcp_http_shark(work_queue, interface, custom_tag, return_deep_info, http_filter, cache_size, session_size, bpf_filter, timeout, debug)
	shark_obj.run()

def pcap_analysis(work_queue):
	pcap_obj = tcp_http_pcap(work_queue, interface, custom_tag, return_deep_info, http_filter, cache_size, session_size, bpf_filter, timeout, debug)
	pcap_obj.run()

class thread_msg_send(threading.Thread):
	def __init__(self, work_queue, msg_obj):

		threading.Thread.__init__(self)
		self.work_queue = work_queue
		self.msg_obj = msg_obj

	def run(self):
		while True:
			try:
				if self.work_queue and self.msg_obj:
					result = self.work_queue.popleft()
					self.msg_obj.info(result)
				else:
					time.sleep(1)
			except:
				pass

if __name__ == '__main__':

	# crontab方式启动
	# */5 * * * * root /usr/bin/python3 /passets-sensor/main.py >> /dev/null 2>&1
	# check_lock()

	try:
		opts,args = getopt.getopt(sys.argv[1:],'i: s: p: d: t: r: c: T: S:')
	except:
		Usage()
	if len(opts) < 3:
		Usage()

	for o, a in opts:
		if o == "-i":
			interface = str(a)
		if o == '-s':
			server_ip = str(a)
		if o == '-t':
			custom_tag = str(a)
		if o == '-p': 
			server_port = int(a)
		if o == '-d':
			debug_str = str(a)
			if debug_str == 'on':
				debug = True
		if o == '-r':
			return_switch_str = str(a)
			if return_switch_str == 'off':
				return_deep_info = False
		if o == '-c':
			cache_size = int(a)
		if o == '-S':
			session_size = int(a)
			if session_size == 0:
				session_size = 1024
		if o == '-T':
			timeout = int(a)

	if interface and server_ip and server_port:
		# 接受通过环境变量传入的过滤设置
		if 'http_filter_code' in os.environ:
			http_filter['response_code'] = list(set(filter(None, os.environ["http_filter_code"].replace(" ","").split(","))))
		if 'http_filter_type' in os.environ:
			http_filter['content_type'] = list(set(filter(None, os.environ["http_filter_type"].replace(" ","").split(","))))
		bpf_filter += ' and not (host {} and port {})'.format(server_ip,server_port)

		try:
			# work_queue = queue.LifoQueue(max_queue_size)
			work_queue = collections.deque(maxlen=max_queue_size)

			if msg_send_mode == "HTTP":
				http_url = "http://{}:{}/".format(server_ip,server_port)
				msg_obj = _http_msg_send(http_url)
			elif msg_send_mode == "SYSLOG":
				msg_obj = _syslog_msg_send(server_ip,server_port)
			else:
				msg_obj = ''
			
			for i in range(msg_send_thread_num):
				msg_thread_obj = thread_msg_send(work_queue, msg_obj)
				msg_thread_obj.start()

			if engine == 'PCAP':
				pcap_analysis(work_queue)
			elif engine == 'TSHARK':
				tshark_analysis(work_queue)
			else:
				pass
		except KeyboardInterrupt:
			print('\nExit.')
			os.kill(os.getpid(),signal.SIGKILL)
		except :
			traceback.print_exc()
	else:
		Usage()