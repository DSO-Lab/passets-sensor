#-*- coding:utf-8 -*-

import logging
import logging.handlers 
import os
import sys
import requests
import socket
import json

# TASK_LOCK_FILE临时文件，判断程序是否正在运行
TASK_LOCK_FILE = sys.path[0]+'/passets_sensor.lock'
global_pid = os.getpid()
if 'win' in sys.platform:
	global_os_version = 'win'
else:
	global_os_version = 'lnx'

def print_log(msg):
	print(msg)

def check_lock():
	try:
		# print_log('[+] check_lock ...')
		if not os.path.isfile(TASK_LOCK_FILE):
			w_lock = open(TASK_LOCK_FILE, 'w')
			w_lock.write(str(global_pid))
			w_lock.close()
		else:
			w_lock = open(TASK_LOCK_FILE, 'r')
			pid_str = w_lock.readline().strip('\n')
			w_lock.close()
			# lnx 判断进程是否存在
			if global_os_version == 'lnx':
				p = os.popen('ps -A | grep "%s"' % pid_str)
				if pid_str and 'python' not in p.read():
					w_lock = open(TASK_LOCK_FILE, 'w')
					w_lock.write(str(global_pid))
					w_lock.close()
				else:
					print_log('[!] passets_sensor already running !')
					sys.exit()
			# win 判断进程是否存在
			else:
				p = os.popen('tasklist /FI "PID eq %s"' % pid_str)
				if pid_str and p.read().count('python') == 0:
					w_lock = open(TASK_LOCK_FILE, 'w')
					w_lock.write(str(global_pid))
					w_lock.close()
				else:
					print_log('[!] passets_sensor already running !')
					sys.exit()
	except Exception as e:
		print_log('[!] check_lock Error !')
		print_log(e)
		sys.exit()

def proc_body_str(data, length):
	"""
	body 按照字节大小截取，防止超长，截取开头2/3和结尾1/3
	:param data: 原始数据
	:param length: 截取的数据长度
	:return: 截断后的数据		
	"""
	if len(data) <= length:
		return data
	head_length = int(length*2//3)
	end_length = length - head_length
	intercept_data_head = data[:head_length]
	intercept_data_end = data[-end_length:]
	return intercept_data_head+intercept_data_end

def proc_body_json(data, length):
	"""
	防止转换为 JSON 后超长的数据截取方法
	:param data: 原始数据
	:param length: 截取的数据长度
	:return: 截断后的数据
	"""
	json_data = json.dumps(data)[:length]
	total_len = len(json_data)
	if total_len < length:
		return data
	
	pos = json_data.rfind("\\u")
	if pos + 6 > len(json_data):
		json_data = json_data[:pos]
	
	return json.loads(json_data.rstrip(r'\"') + '"')

def proc_data_str(data, length):
	"""
	data 按照字节大小阶段，防止超长，从起始位置开始截取
	:param data: 原始数据的HEX字符串
	:param length: 截取的数据长度
	:return: 截断后的数据
	"""
	if len(data) <= length * 2:
		return data

	return data[: length * 2]

# Syslog Send
class _syslog_msg_send:
	def __init__(self, server_ip, server_port):

		self.server_ip = server_ip
		self.server_port = server_port
		self.logger = logging.getLogger()
		hdlr = logging.handlers.SysLogHandler((self.server_ip, self.server_port), logging.handlers.SysLogHandler.LOG_AUTH)
		# hdlr = logging.handlers.RotatingFileHandler(logfile, maxBytes=5242880, backupCount=5)
		formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
		hdlr.setFormatter(formatter)
		self.logger.addHandler(hdlr)
		self.logger.setLevel(logging.INFO)

	def info(self, msg):
		self.logger.info(msg)

	def warning(self, msg):
		self.logger.warning(msg)

	def error(self, msg):
		self.logger.error(msg)

	def exception(self, msg):
		self.logger.exception(msg)

	def critical(self, msg):
		self.logger.critical(msg)

# HTTP Send
class _http_msg_send:
	def __init__(self,http_url):
		self.http_url = http_url
	def info(self,msg):
		self.req = requests.post(self.http_url, data=msg, verify=False, timeout=2)

# TCP Send
class _tcp_msg_send:
	def __init__(self,server_ip,server_port):
		self.server_ip = server_ip
		self.server_port = server_port
		self.tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		#心跳维护
		self.tcp_client.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
		self.tcp_client.connect((self.server_ip, self.server_port))

	def info(self,msg):
		try:
			self.tcp_client.send(msg.encode()+b"\n")
			return True
		except socket.error as e:
			if e.errno == 32:
				return False
		# self.tcp_client.close()
