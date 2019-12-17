#-*- coding:utf-8 -*-

import pyshark
import json
import base64
import time
import re
import traceback
import concurrent.futures
from ._logging import _logging
from cacheout import Cache

class tcp_http_sniff():

	def __init__(self,interface,display_filter,syslog_ip,syslog_port,custom_tag,return_deep_info,filter_rules,cache_size,bpf_filter,timeout,debug):
		self.debug = debug
		self.timeout = timeout
		self.bpf_filter = bpf_filter
		self.cache_size = cache_size
		self.filter_rules = filter_rules
		self.return_deep_info = return_deep_info
		self.custom_tag = custom_tag
		self.syslog_ip = syslog_ip
		self.syslog_port = syslog_port
		self.log_obj = _logging(self.syslog_ip,self.syslog_port)
		self.interface = interface
		self.display_filter = display_filter
		self.pktcap = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.bpf_filter, display_filter=self.display_filter, debug=self.debug)
		self.http_cache = Cache(maxsize=self.cache_size, ttl=120, timer=time.time, default=None)
		self.tcp_cache = Cache(maxsize=self.cache_size, ttl=120, timer=time.time, default=None)
		# 检测页面编码的正则表达式
		self.encode_regex = re.compile(b'<meta [^>]*?charset=["\']?([^"\'\s]+)["\']?', re.I)

	# 根据response_code和content_type过滤
	def http_filter(self,key,value):
		if key in self.filter_rules:
			for rule in self.filter_rules[key]:
				if rule in value:
					return True
		return False
	
	def run(self):
		try:
			self.pktcap.apply_on_packets(self.proc_packet,timeout=self.timeout)
		except concurrent.futures.TimeoutError:
			print("\nTimeoutError.")
	def proc_packet(self, pkt):
		try:
			pkt_json = None
			pkt_dict = dir(pkt)
			
			if 'ip' in pkt_dict:
				if 'http' in pkt_dict:
					pkt_json = self.proc_http(pkt)
				elif 'tcp' in pkt_dict:
					pkt_json = self.proc_tcp(pkt)

			if pkt_json:
				if self.debug:
					print(json.dumps(pkt_json))
				self.log_obj.info(json.dumps(pkt_json))

		except Exception:
			traceback.format_exc()
			# error_log_json = {}
			# error_log_json["custom_tag"] = self.custom_tag
			# error_log_json["error_log"] = str(traceback.format_exc())
			# if self.debug:
			# 	print(json.dumps(error_log_json))
			# self.log_obj.error(json.dumps(error_log_json))
	
	def proc_http(self, pkt):
		http_dict = dir(pkt.http)
		
		if self.return_deep_info:
			if 'request' in http_dict:
				self.http_cache.set(pkt.tcp.stream, pkt.http.request_full_uri if 'request_full_uri' in http_dict else pkt.http.request_uri)
		
		if 'response' in http_dict:
			pkt_json = {}
			src_addr = pkt.ip.src
			src_port = pkt[pkt.transport_layer].srcport
			
			cache_url = self.http_cache.get(pkt.tcp.stream)
			if cache_url:
				pkt_json['url'] = cache_url
				self.http_cache.delete(pkt.tcp.stream)
			
			if 'url' not in pkt_json:
				if 'response_for_uri' in http_dict:
					pkt_json["url"] = pkt.http.response_for_uri
				else:
					pkt_json["url"] = '/'

			# 处理 URL 只有URI的情况
			if pkt_json["url"][0] == '/':
				if src_port == '80':
					pkt_json["url"] = "http://%s%s"%(src_addr,pkt_json["url"])
				else:
					pkt_json["url"] = "http://%s:%s%s"%(src_addr,src_port,pkt_json["url"])

			# 缓存机制，防止短时间大量处理重复响应
			exists = self.http_cache.get(pkt_json['url'])
			if exists:
				return None

			self.http_cache.set(pkt_json["url"], True)

			pkt_json["pro"] = 'HTTP'
			pkt_json["tag"] = self.custom_tag
			pkt_json["ip"] = src_addr
			pkt_json["port"] = src_port

			if 'response_code' in http_dict:
				if self.filter_rules:
					return_status = self.http_filter('response_code', pkt.http.response_code)
					if return_status:
						return None
				pkt_json["code"] = pkt.http.response_code
			
			if 'content_type' in http_dict:
				if self.filter_rules:
					return_status = self.http_filter('content_type', pkt.http.content_type)
					if return_status:
						return None
				pkt_json["type"] = pkt.http.content_type.lower()
			else:
				pkt_json["type"] = 'unkown'

			if 'server' in http_dict:
				pkt_json["server"] = pkt.http.server

			# -r on开启深度数据分析，返回header和body等数据
			if self.return_deep_info:
				charset = 'utf-8'
				# 检测 Content-Type 中的编码信息
				if 'type' in pkt_json and 'charset=' in pkt_json["type"]:
					charset = pkt_json["type"][pkt_json["type"].find('charset=')+8:].strip().lower()
					if not charset :
						charset = 'utf-8'
				if 'payload' in dir(pkt.tcp):
					payload = bytes.fromhex(str(pkt.tcp.payload).replace(':', ''))
					if payload.find(b'HTTP/') == 0:
						split_pos = payload.find(b'\r\n\r\n')
						if split_pos <= 0 or split_pos > 4096:
							split_pos = 4096
						pkt_json["header"] = str(payload[:split_pos], 'utf-8', 'ignore')

				if 'file_data' in http_dict and pkt.http.file_data.raw_value and pkt_json['type'] != 'application/octet-stream':
					data = bytes.fromhex(pkt.http.file_data.raw_value)
					# 检测页面 Meta 中的编码信息
					data_head = data[:500] if data.find(b'</head>', 0, 1024) == -1 else data[:data.find(b'</head>')]
					match = self.encode_regex.search(data_head)
					if match:
						charset = str(match.group(1).lower(), 'utf-8', 'ignore')
					response_body = self.proc_body(str(data, charset, 'ignore'), 16*1024)
					pkt_json["body"] = response_body
				else:
					pkt_json["body"] = ''
			
			return pkt_json
		
		return None

	def proc_tcp(self, pkt):
		tcp_stream = pkt.tcp.stream
		
		pkt_json = {}
		pkt_json["pro"] = 'TCP'
		pkt_json["tag"] = self.custom_tag

		# SYN+ACK
		if pkt.tcp.flags == '0x00000012' : 
			server_ip = pkt.ip.src
			server_port = pkt[pkt.transport_layer].srcport
			tcp_info = '%s:%s' % (server_ip, server_port)

			exists = self.tcp_cache.get(tcp_info)
			if exists:
				return None
				
			if self.return_deep_info and tcp_info:
				self.tcp_cache.set(tcp_stream, tcp_info)
				self.tcp_cache.set(tcp_info,True)
			else:
				pkt_json["ip"] = server_ip
				pkt_json["port"] = server_port
				self.tcp_cache.set(tcp_info,True)
				return pkt_json
		
		# -r on开启深度数据分析，采集server第一个响应数据包
		if self.return_deep_info and pkt.tcp.seq == "1" and "payload" in dir(pkt.tcp) :
			tcp_info = self.tcp_cache.get(tcp_stream)
			if tcp_info:
				tcp_info_list = tcp_info.split(":")
				tcp_ip = tcp_info_list[0]
				tcp_port = tcp_info_list[1]
				pkt_json["ip"] = tcp_ip
				pkt_json["port"] = tcp_port
				payload_data = pkt.tcp.payload.replace(":","")
				# if payload_data.startswith("48545450"):
				# 	return None
				# HTTPS Protocol
				# TODO: other https port support 
				if tcp_port == "443" and payload_data.startswith("1603"):
					pkt_json["pro"] = 'HTTPS'
					pkt_json["url"] = "https://%s/"%(tcp_ip)
				else:
					pkt_json["data"] = payload_data
				self.tcp_cache.delete(tcp_stream)
				return pkt_json
		return None

	def proc_body(self, data, length):
		json_data = json.dumps(data)[:length]
		total_len = len(json_data)
		if total_len < length:
			return data
		
		pos = json_data.rfind("\\u")
		if pos + 6 > len(json_data):
			json_data = json_data[:pos]
		
		return json.loads(json_data + '"')
