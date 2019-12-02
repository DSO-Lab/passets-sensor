#-*- coding:utf-8 -*-

import pyshark
import json
import base64
import time
import traceback
from ._logging import _logging
from cacheout import Cache

class tcp_http_sniff():

	def __init__(self,interface,display_filter,syslog_ip,syslog_port,display_switch,custom_tag,return_http_info,filter_rules):
		self.filter_rules = filter_rules
		self.return_http_info = return_http_info
		self.custom_tag = custom_tag
		self.syslog_ip = syslog_ip
		self.syslog_port = syslog_port
		self.log_obj = _logging(self.syslog_ip,self.syslog_port)
		self.interface = interface
		self.display_filter = display_filter
		self.display_switch = display_switch
		self.pktcap = pyshark.LiveCapture(interface=self.interface, bpf_filter=self.display_filter)
		self.cache = Cache(maxsize=256, ttl=120, timer=time.time, default=None)

	# 根据response_code和content_type过滤
	def http_filter(self,key,value):
		if key in self.filter_rules:
			for rule in self.filter_rules[key]:
				if rule in value:
					return True
		return False
	
	def run(self):
		self.pktcap.apply_on_packets(self.proc_packet)

	def proc_packet(self, pkt):
		try:
			pkt_json = None
			pkt_dict = dir(pkt)
			
			if 'ip' in pkt_dict:
				if 'http' in pkt_dict:
					pkt_json = self.proc_http(pkt)
				# 非HTTP回话，只提取tcp flags == syn+ack的数据包，方便确定数据流向(服务方 --> 发起方)
				elif 'tcp' in pkt_dict:
					pkt_json = self.proc_tcp(pkt)

			if pkt_json:
				if self.display_switch:
					print(json.dumps(pkt_json))
				self.log_obj.info(json.dumps(pkt_json))

		except Exception:
			traceback.format_exc()
			# error_log_json = {}
			# error_log_json["custom_tag"] = self.custom_tag
			# error_log_json["error_log"] = str(traceback.format_exc())
			# if self.display_switch:
			# 	print(json.dumps(error_log_json))
			# self.log_obj.error(json.dumps(error_log_json))
	
	def proc_http(self, pkt):
		http_dict = dir(pkt.http)
		
		if self.return_http_info:
			if 'request' in http_dict:
				self.cache.set(pkt.tcp.stream, pkt.http.request_full_uri if 'request_full_uri' in http_dict else pkt.http.request_uri)
		
		if 'response' in http_dict:
			pkt_json = {}
			src_addr = pkt.ip.src
			src_port = pkt[pkt.transport_layer].srcport
			
			if self.return_http_info:
				cache_url = self.cache.get(pkt.tcp.stream)
				if cache_url:
					pkt_json['http_uri'] = cache_url
					self.cache.delete(pkt.tcp.stream)
			
			if 'http_uri' not in pkt_json:
				if 'response_for_uri' in http_dict:
					pkt_json["http_uri"] = pkt.http.response_for_uri
				else:
					pkt_json["http_uri"] = '/'

			# 处理 URL 只有URI的情况
			if pkt_json["http_uri"][0] == '/':
				if src_port == '80':
					pkt_json["http_uri"] = "http://%s%s"%(src_addr,pkt_json["http_uri"])
				else:
					pkt_json["http_uri"] = "http://%s:%s%s"%(src_addr,src_port,pkt_json["http_uri"])
			
			# 缓存机制，防止短时间大量处理重复响应
			exists = self.cache.get(pkt_json['http_uri'])
			if exists:
				return None

			self.cache.set(pkt_json["http_uri"], True)

			pkt_json["protocol"] = 'HTTP'
			pkt_json["custom_tag"] = self.custom_tag
			pkt_json["src_addr"] = src_addr
			pkt_json["src_port"] = src_port
			pkt_json["dst_addr"] = pkt.ip.dst
			pkt_json["dst_port"] = pkt[pkt.transport_layer].dstport

			if 'response_code' in http_dict:
				if self.filter_rules:
					return_status = self.http_filter('response_code', pkt.http.response_code)
					if return_status:
						return None
				pkt_json["response_code"] = pkt.http.response_code
			
			if 'content_type' in http_dict:
				if self.filter_rules:
					return_status = self.http_filter('content_type', pkt.http.content_type)
					if return_status:
						return None
				pkt_json["content_type"] = pkt.http.content_type.lower()
			else:
				pkt_json["content_type"] = 'unkown'

			if 'server' in http_dict:
				pkt_json["http_server"] = pkt.http.server

			# -r on开启http详细回显，返回headers和response body等数据
			if self.return_http_info:
				charset = 'windows-1252'
				# 根据Content-Type处理编码
				if 'content_type' in pkt_json:
					# 提取头中的编码
					if 'gbk' in pkt_json["content_type"] or 'gb2312' in pkt_json["content_type"]:
						charset = 'gbk'
					elif 'utf-8' in pkt_json["content_type"]:
						charset = 'utf-8'
						
				if 'payload' in dir(pkt.tcp):
					payload = bytes.fromhex(str(pkt.tcp.payload).replace(':', ''))
					if payload.find(b'HTTP/') == 0:
						split_pos = payload.find(b'\r\n\r\n')
						if split_pos <= 0 or split_pos > 4096:
							split_pos = 4096
						pkt_json["response_headers"] = str(payload[:split_pos], 'utf-8', 'ignore')

				if 'file_data' in http_dict and pkt.http.file_data.raw_value and pkt_json['content_type'] != 'application/octet-stream':
					data = bytes.fromhex(pkt.http.file_data.raw_value)
					# 根据页面HEAD处理编码
					data_head = data[:500] if data.find(b'</head>', 0, 1024) == -1 else data[:data.find(b'</head>')]
					data_head_str = str(data_head, 'utf-8', 'ignore').lower()
					if 'charset=gbk' in data_head_str or 'charset=gb2312' in data_head_str:
						charset = 'gbk'
					elif 'charset=utf-8' in data_head_str:
						charset = 'utf-8'
					
					response_body = self.proc_body(str(data, charset, 'ignore'), 16*1024)
					pkt_json["response_body"] = response_body
				else:
					pkt_json["response_body"] = ''
			
			return pkt_json
		
		return None

	def proc_tcp(self, pkt):
		# 部分情况下 flags 需要使用 18
		if pkt.tcp.flags == '0x00000012': # SYN+ACK
			pkt_json = {}
			pkt_json["protocol"] = 'TCP'
			pkt_json["custom_tag"] = self.custom_tag
			pkt_json["src_addr"] = pkt.ip.src
			pkt_json["src_port"] = pkt[pkt.transport_layer].srcport
			pkt_json["dst_addr"] = pkt.ip.dst
			pkt_json["dst_port"] = pkt[pkt.transport_layer].dstport

			src = 'tcp://%s:%s' % (pkt_json["src_addr"], pkt_json["src_port"])
			exists = self.cache.get(src)
			if exists:
				return None
			
			self.cache.set(src, True)
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
