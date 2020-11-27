#-*- coding:utf-8 -*-

from lib._http_tcp_shark import tcp_http_shark
from lib._http_tcp_pcap import tcp_http_pcap
from lib._util import check_lock
from lib._util import _syslog_msg_send, _http_msg_send, _tcp_msg_send
import getopt
import sys
import os
import threading
# import queue
import collections
import signal
import traceback
import time
import json

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
display_filter = 'tcp'
# debug模式，数据console输出
debug = False
# 记录请求数据
record_request = False
# 开启深度数据分析（Chunked/Gzip重组/解压数据对性能影响较大）
deep_info = True
# 重复缓存数量
cache_size = 4096
# 流量会话数量
session_size = 4096
# tshark定期清空内存（单位秒/默认一小时），pcap接收数据包的超时时间（单位毫秒/默认3.6秒）
timeout = 3600
# 发送数据线程数量
msg_send_thread_num = 2
# 发送数据队列最大值
max_queue_size = 50000
# 资产数据发送模式，仅支持TCP，HTTP，SYSLOG三种
msg_send_mode = 'TCP'
# 流量采集引擎，仅支持TSHARK，PCAP两种
engine = "PCAP"
# pcap采集数据类型控制，TCP，HTTP
allow_protocols = 'TCP/HTTP'

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

 -c <cache_size>    Cache size(def: 1024)
 -d <off|on>        Debug information switch(def: off)
 -e <off|on>        Record request info(def: off)
 -i <interface>     Name or idx of interface(def: None)		 
 -p <server_port>   server port(def: None)
 -r <deep_info>	    Deep packet analysis(def: off)
 -s <server_ip>     server ip(def: None)
 -t <tag>           Source identification(def: localhost)
 -P <protocols>     Protocol: TCP, HTTP or TCP/HTTP
 -S <session_size>  Session size(def: 1024)
 -T <timeout>       Memory clear time(def: 3600 sec)
 -------------------------------------------------------------------
	''')
	sys.exit()

def tshark_analysis(work_queue):

	shark_obj = tcp_http_shark(work_queue, interface, custom_tag, deep_info, record_request, http_filter, cache_size, session_size, bpf_filter, timeout, debug)
	shark_obj.run()

def pcap_analysis(work_queue):
	pcap_obj = tcp_http_pcap(allow_protocols, int(max_queue_size), work_queue, interface, custom_tag, deep_info, record_request, http_filter, cache_size, session_size, bpf_filter, timeout, debug)
	pcap_obj.run()

class thread_msg_send(threading.Thread):
	def __init__(self, work_queue, msg_send_mode):

		threading.Thread.__init__(self)
		self.work_queue = work_queue
		self.msg_send_mode = msg_send_mode
		self.msg_obj = self.msg_obj_fun(self.msg_send_mode)

	def msg_obj_fun(self, msg_send_mode):
		if msg_send_mode == "TCP":
			msg_obj = _tcp_msg_send(server_ip,server_port)
		elif msg_send_mode == "HTTP":
			http_url = "http://{}:{}/".format(server_ip,server_port)
			msg_obj = _http_msg_send(http_url)
		elif msg_send_mode == "SYSLOG":
			msg_obj = _syslog_msg_send(server_ip,server_port)
		else:
			msg_obj = ''
		return msg_obj

	def run(self):
		tcp_flag = True if self.msg_obj else False
		# total_msg_num = 0
		while True:
			# start = time.time()
			if not tcp_flag:
				self.msg_obj = self.msg_obj_fun(self.msg_send_mode)
			if len(self.work_queue):
				result = self.work_queue.popleft()
				if msg_send_mode == "TCP":
					tcp_flag = self.msg_obj.info(result)
					# total_msg_num += 1
					# if total_msg_num%100 == 0:
						# end = time.time()
						# print("Used Time: %s"%(end - start))
				else:
					self.msg_obj.info(result)

	
if __name__ == '__main__':

	# 宿主机crontab方式启动
	# */5 * * * * root /usr/bin/python3 /passets-sensor/main.py >> /dev/null 2>&1
	# check_lock()

	try:
		opts,args = getopt.getopt(sys.argv[1:],'c: d: e: i: p: r: s: t: P: S: T:')
	except:
		Usage()
	if len(opts) < 3:
		Usage()

	for o, a in opts:
		if o == '-c':
			cache_size = int(a)
		elif o == '-d':
			debug_str = str(a)
			if debug_str == 'on':
				debug = True
		elif o == '-e':
			record_str = str(a)
			if record_str == 'on':
				record_request = True
		elif o == "-i":
			interface = str(a)
		elif o == '-p': 
			server_port = int(a)
		elif o == '-r':
			deep_str = str(a)
			if deep_str == 'off':
				deep_info = False
		elif o == '-s':
			server_ip = str(a)
		elif o == '-t':
			custom_tag = str(a)
		elif o == '-P':
			allow_protocols = str(a)
		elif o == '-S':
			session_size = int(a)
			if session_size == 0:
				session_size = 1024
		elif o == '-T':
			timeout = int(a)
		
	if interface and server_ip and server_port:
		# 接受通过环境变量传入的过滤设置
		if 'http_filter_code' in os.environ:
			http_filter['response_code'] = list(set(filter(None, os.environ["http_filter_code"].replace(" ","").split(","))))
		if 'http_filter_type' in os.environ:
			http_filter['content_type'] = list(set(filter(None, os.environ["http_filter_type"].replace(" ","").split(","))))
		bpf_filter += ' and not (host {} and port {}) and not (host 127.0.0.1 or host localhost) '.format(server_ip,server_port)
		print('HTTP Filter:\n' + json.dumps(http_filter))

		try:
			work_queue = collections.deque(maxlen=int(max_queue_size))
			
			for i in range(msg_send_thread_num):
				msg_thread_obj = thread_msg_send(work_queue, msg_send_mode)
				msg_thread_obj.setDaemon(True)
				msg_thread_obj.start()

			if engine == 'PCAP':
				pcap_analysis(work_queue)
			elif engine == 'TSHARK':
				tshark_analysis(work_queue)

		except KeyboardInterrupt:
			print('\nExit.')
			os.kill(os.getpid(), signal.SIGKILL)
		except :
			traceback.print_exc()
	else:
		Usage()