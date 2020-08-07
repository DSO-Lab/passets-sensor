#-*- coding:utf-8 -*-

import pcap
import dpkt
import time
import json
import sys
import re
import io
import gzip
import brotli
import os
from cacheout import Cache, LRUCache

class tcp_http_pcap():

	def __init__(self, pcap_collection_data, max_queue_size, work_queue, interface, custom_tag, return_deep_info, http_filter_json, cache_size, session_size, bpf_filter, timeout, debug):
		"""
		构造函数
		:param max_queue_size: 资产队列最大长度
		:param work_queue: 捕获资产数据消息发送队列
		:param interface: 捕获流量的网卡名
		:param custom_tag: 数据标签，用于区分不同的采集引擎
		:param return_deep_info: 是否处理更多信息，包括原始请求、响应头和正文
		:param http_filter_json: HTTP过滤器配置，支持按状态和内容类型过滤
		:param cache_size: 缓存的已处理数据条数，120秒内重复的数据将不会重复采集
		:param session_size: 缓存的HTTP/TCP会话数量，30秒未使用的会话将被自动清除
		:param bpf_filter: 数据包底层过滤器
		:param timeout: 采集程序的运行超时时间，默认为启动后1小时自动退出
		:param debug: 调试开关
		"""
		self.pcap_collection_data = pcap_collection_data
		self.total_msg_num = 0
		self.max_queue_size = max_queue_size
		self.work_queue = work_queue
		self.debug = debug
		self.timeout = timeout
		self.bpf_filter = bpf_filter
		self.cache_size = cache_size
		self.session_size = session_size
		self.http_filter_json = http_filter_json
		self.return_deep_info = return_deep_info
		self.custom_tag = custom_tag
		self.interface = interface
		self.sniffer = pcap.pcap(self.interface, snaplen=65535, promisc=True, timeout_ms=self.timeout, immediate=False)
		self.sniffer.setfilter(self.bpf_filter)
		self.tcp_stream_cache = Cache(maxsize=self.session_size, ttl=30, timer=time.time, default=None)
		if self.cache_size:
			self.tcp_cache = LRUCache(maxsize=self.cache_size, ttl=120, timer=time.time, default=None)
			self.http_cache = LRUCache(maxsize=self.cache_size, ttl=120, timer=time.time, default=None)
		# http数据分析正则
		self.decode_request_regex = re.compile(r'^([A-Z]+) +([^ \r\n]+) +HTTP/\d+(?:\.\d+)?[^\r\n]*(.*?)$', re.S)
		self.decode_response_regex = re.compile(r'^HTTP/(\d+(?:\.\d+)?) (\d+)[^\r\n]*(.*?)$', re.S)
		self.decode_body_regex = re.compile(rb'<meta[^>]+?charset=[\'"]?([a-z\d\-]+)[\'"]?', re.I)

	def run(self):
		"""
		入口函数
		"""
		for ts, pkt in self.sniffer:
			# self.total_msg_num += 1
			# if self.total_msg_num%1000 == 0:
			# 	print("Packet analysis rate: %s"%(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())+" - "+str(self.total_msg_num)))
			packet = self.pkt_decode(pkt)
			if not packet:
				continue
			
			# print('{}:{}->{}:{}: Seq:{}, Ack:{}, Flag: {}, Len: {}'.format(packet.src, packet.sport, packet.dst, packet.dport, packet.ack, packet.seq, packet.flags, len(packet.data)))
			cache_key = '{}:{}'.format(packet.src, packet.sport)
			# SYN & ACK
			if packet.flags == 0x12:
				if self.cache_size and self.tcp_cache.get(cache_key):
					continue
				
				self.tcp_stream_cache.set('S_{}'.format(packet.ack), packet.seq + 1)
			
			# ACK || PSH-ACK
			elif packet.flags in [0x10, 0x18, 0x19]:
				# 长度为0的数据包不处理
				if len(packet.data) == 0:
					continue

				# 第一个有数据的请求包，先缓存下来
				# Seq == SYN-ACK Ack
				pre_cs_seq = self.tcp_stream_cache.get('S_{}'.format(packet.seq))
				if pre_cs_seq:
					c_s_key = 'C_{}'.format(packet.ack)
					
					self.tcp_stream_cache.set(c_s_key, packet.data)
					self.tcp_stream_cache.delete('S_{}'.format(packet.seq))
					continue

				# 1. 提取服务器主动响应的通讯，例如：MySQL
				# Seq == SYN-ACK Seq + 1
				if 'TCP' in self.pcap_collection_data:
					pre_sc_seq = self.tcp_stream_cache.get('S_{}'.format(packet.ack))
					if pre_sc_seq == packet.seq:
						self.tcp_stream_cache.delete('S_{}'.format(packet.ack))

						# TCP瞬时重复处理
						if self.cache_size:
							self.tcp_cache.set(cache_key, True)
						
						data = {
							'pro': 'TCP',
							'tag': self.custom_tag,
							'ip': packet.src,
							'port': packet.sport,
							'data': packet.data.hex()
						}
						self.send_msg(data)
						continue

				# 2. 提取需要请求服务器才会响应的通讯，例如：HTTP
				# Seq == PSH ACK(C->S) Ack
				send_data = self.tcp_stream_cache.get('C_{}'.format(packet.seq))
				# 判断是否存在请求数据
				if send_data:
					# 删除已使用的缓存
					self.tcp_stream_cache.delete('C_{}'.format(packet.seq))
				
					# HTTP通讯采集判断
					if 'HTTP' in self.pcap_collection_data and packet.data[:5] == b'HTTP/':
						request_dict = self.decode_request(send_data, packet.src, str(packet.sport))
						if not request_dict:
							continue

						http_cache_key = '{}:{}'.format(request_dict['method'], request_dict['uri'])
						if self.cache_size and self.http_cache.get(http_cache_key):
							continue
						
						response_dict = self.decode_response(packet.data)
						if response_dict:
							# HTTP瞬时重复处理
							if self.cache_size:
								self.http_cache.set(http_cache_key, True)
								
							response_code = response_dict['status']
							content_type = response_dict['type']

							# 根据响应状态码和页面类型进行过滤
							if self.http_filter_json:
								filter_code = self.http_filter('response_code', response_code) if response_code else False
								filter_type = self.http_filter('content_type', content_type) if content_type else False
								if filter_code or filter_type:
									continue
							
							data = {
								'pro': 'HTTP',
								'tag': self.custom_tag,
								'ip': packet.src,
								'port': packet.sport,
								'method': request_dict['method'],
								'code': response_code,
								'type': content_type,
								'server': response_dict['server'],
								'header': response_dict['headers'],
								'url': request_dict['uri'],
								'body': response_dict['body']
							}

							self.send_msg(data)
							continue
					
					# TCP通讯采集判断
					elif 'TCP' in self.pcap_collection_data:
						# TCP瞬时重复处理
						if self.cache_size:
							self.tcp_cache.set(cache_key, True)
						
						# 2.2 非 HTTP 通讯
						data = {
							'pro': 'TCP',
							'tag': self.custom_tag,
							'ip': packet.src,
							'port': packet.sport,
							'data': packet.data.hex()
						}
						self.send_msg(data)
					
		self.sniffer.close()

	def http_filter(self, key, value):
		"""
		检查字符串中是否包含特定的规则
		:param key: 规则键名，response_code（状态码）或 content_type（内容类型）
		:param value: 要检查的字符串
		:return: True - 包含， False - 不包含
		"""
		if key in self.http_filter_json:
			for rule in self.http_filter_json[key]:
				if rule in value:
					return True
		return False

	def pkt_decode(self, pkt):
		try:
			ip_type = ''
			packet = dpkt.ethernet.Ethernet(pkt)
			if isinstance(packet.data, dpkt.ip.IP):
				ip_type = 'ip4'
			elif isinstance(packet.data, dpkt.ip6.IP6):
				ip_type = 'ip6'
			if ip_type and isinstance(packet.data.data, dpkt.tcp.TCP):
				if packet.data.data.flags == 0x12 or \
					packet.data.data.flags in [0x10, 0x18, 0x19] and len(packet.data.data.data) > 0:
					tcp_pkt = packet.data.data
					if ip_type == 'ip4':
						tcp_pkt.src = self.ip_addr(packet.data.src)
						tcp_pkt.dst = self.ip_addr(packet.data.dst)
					else:
						tcp_pkt.src = self.ip6_addr(''.join(['%02X' %x  for x in packet.data.src]))
						tcp_pkt.dst = self.ip6_addr(''.join(['%02X' %x  for x in packet.data.dst]))
					return tcp_pkt
		except KeyboardInterrupt:
			print('\nExit.')
			os.kill(os.getpid(),signal.SIGKILL)
		except Exception as e:
			# print(str(e))
			# print(("".join(['%02X ' % b for b in pkt])))
			pass
		return None

	def ip_addr(self, ip):
		return '%d.%d.%d.%d'%tuple(ip)

	def ip6_addr(self,ip6):
		ip6_addr = ''
		ip6_list = re.findall(r'.{4}', ip6)
		for i in range(len(ip6_list)):
			ip6_addr += ':%s'%(ip6_list[i].lstrip('0') if ip6_list[i].lstrip('0') else '0')
		return ip6_addr.lstrip(':')

	def decode_request(self, data, sip, sport):
		pos = data.find(b'\r\n\r\n')
		body = data[pos+4:] if pos > 0 else b''
		data_str = str(data[:pos] if pos > 0 else data, 'utf-8', 'ignore')
		m = self.decode_request_regex.match(data_str)
		if m:
			if m.group(2)[:1] != '/':
				return None
			
			headers = m.group(3).strip() if m.group(3) else ''
			header_dict = self.parse_headers(headers)
			host_domain = ''
			# host domain
			if 'host' in header_dict and re.search('[a-zA-Z]', header_dict['host']):
				host_domain = header_dict['host']
			# host ip
			else:
				host_domain = sip+':'+sport if sport != '80' else sip 
			url = 'http://{}{}'.format(host_domain, m.group(2)) if host_domain else m.group(2)
			
			return {
				'method': m.group(1) if m.group(1) else '',
				'uri': url,
				'headers': headers,
				'body': str(body, 'utf-8', 'ignore')
			}

		return {'method':'', 'uri':'http://{}:{}/'.format(sip if ':' not in sip else '['+sip+']' , sport), 'headers':'', 'body':''}

	def decode_response(self, data):
		pos = data.find(b'\r\n\r\n')
		body = data[pos+4:] if pos > 0 else b''
		header_str = str(data[:pos] if pos > 0 else data, 'utf-8', 'ignore')
		m = self.decode_response_regex.match(header_str)
		if m:
			headers = m.group(3).strip() if m.group(3) else ''
			headers_dict = self.parse_headers(headers)
			if self.return_deep_info and 'transfer-encoding' in headers_dict and headers_dict['transfer-encoding'] == 'chunked':
				body = self.decode_chunked(body)

			if self.return_deep_info and 'content-encoding' in headers_dict:
				if headers_dict['content-encoding'] == 'gzip':
					body = self.decode_gzip(body)
				elif headers_dict['content-encoding'] == 'br':
					body = self.decode_brotli(body)

			content_type = '' if 'content-type' not in headers_dict else headers_dict['content-type']
			server = '' if 'server' not in headers_dict else headers_dict['server']
			return {
				'version': m.group(1) if m.group(1) else '',
				'status': m.group(2) if m.group(2) else '',
				'headers': headers,
				'type': content_type,
				'server': server,
				'body': self.decode_body(body, content_type)
			}
		
		return None

	def decode_gzip(self, data):
		'''
		还原 HTTP 响应中采用 gzip 压缩的数据
		标识：
		Content-Encoding: gzip
		'''
		try:
			buf = io.BytesIO(data)
			gf = gzip.GzipFile(fileobj = buf)
			content = gf.read()
			gf.close()

			return content
		except:
			return data

	def decode_brotli(self, data):
		'''
		还原 HTTP 响应中采用 brotli 压缩的数据
		标识：
		Content-Encoding: br
		'''
		try:
			return brotli.decompress(data)
		except:
			return data

	def decode_chunked(self, data):
		'''
		还原 HTTP 响应中被 Chunked 的数据
		示例:
		Transfer-Encoding: chunked

		1b
		{"ret":0, "messge":"error"}
		'''
		line_end = data.find(b'\r\n')
		if line_end > 0:
			data_len = -1
			try:
				data_len = int(data[: line_end], 16)
				if data_len == 0:
					return b''
				
				if data_len > 0:
					new_data = data[line_end + 2: line_end + 2 + data_len]
					return new_data + self.decode_chunked(data[line_end + 2 + data_len + 2: ])
			except:
				return data
			
		return data

	def decode_body(self, data, content_type):
		charset_white_list = ['big5','big5-hkscs','cesu-8','euc-jp','euc-kr','gb18030','gb2312','gbk','ibm-thai','ibm00858','ibm01140','ibm01141','ibm01142','ibm01143','ibm01144','ibm01145','ibm01146','ibm01147','ibm01148','ibm01149','ibm037','ibm1026','ibm1047','ibm273','ibm277','ibm278','ibm280','ibm284','ibm285','ibm290','ibm297','ibm420','ibm424','ibm437','ibm500','ibm775','ibm850','ibm852','ibm855','ibm857','ibm860','ibm861','ibm862','ibm863','ibm864','ibm865','ibm866','ibm868','ibm869','ibm870','ibm871','ibm918','iso-10646-ucs-2','iso-2022-cn','iso-2022-jp','iso-2022-jp-2','iso-2022-kr','iso-8859-1','iso-8859-10','iso-8859-13','iso-8859-15','iso-8859-16','iso-8859-2','iso-8859-3','iso-8859-4','iso-8859-5','iso-8859-6','iso-8859-7','iso-8859-8','iso-8859-9','jis_x0201','jis_x0212-1990','koi8-r','koi8-u','shift_jis','tis-620','us-ascii','utf-16','utf-16be','utf-16le','utf-32','utf-32be','utf-32le','utf-8','windows-1250','windows-1251','windows-1252','windows-1253','windows-1254','windows-1255','windows-1256','windows-1257','windows-1258','windows-31j','x-big5-hkscs-2001','x-big5-solaris','x-euc-jp-linux','x-euc-tw','x-eucjp-open','x-ibm1006','x-ibm1025','x-ibm1046','x-ibm1097','x-ibm1098','x-ibm1112','x-ibm1122','x-ibm1123','x-ibm1124','x-ibm1166','x-ibm1364','x-ibm1381','x-ibm1383','x-ibm300','x-ibm33722','x-ibm737','x-ibm833','x-ibm834','x-ibm856','x-ibm874','x-ibm875','x-ibm921','x-ibm922','x-ibm930','x-ibm933','x-ibm935','x-ibm937','x-ibm939','x-ibm942','x-ibm942c','x-ibm943','x-ibm943c','x-ibm948','x-ibm949','x-ibm949c','x-ibm950','x-ibm964','x-ibm970','x-iscii91','x-iso-2022-cn-cns','x-iso-2022-cn-gb','x-iso-8859-11','x-jis0208','x-jisautodetect','x-johab','x-macarabic','x-maccentraleurope','x-maccroatian','x-maccyrillic','x-macdingbat','x-macgreek','x-machebrew','x-maciceland','x-macroman','x-macromania','x-macsymbol','x-macthai','x-macturkish','x-macukraine','x-ms932_0213','x-ms950-hkscs','x-ms950-hkscs-xp','x-mswin-936','x-pck','x-sjis','x-sjis_0213','x-utf-16le-bom','x-utf-32be-bom','x-utf-32le-bom','x-windows-50220','x-windows-50221','x-windows-874','x-windows-949','x-windows-950','x-windows-iso2022jp']
		content_type = content_type.lower() if content_type else ''
		if 'charset=' in content_type:
			charset = content_type[content_type.find('charset=')+8:].strip('" ;\r\n').lower()
			if charset != 'iso-8859-1' and charset in charset_white_list:
				return str(data, charset, 'ignore')
		
		m = self.decode_body_regex.match(data)
		if m:
			charset = m.group(1).lower() if m.group(1) else ''
			if charset != 'iso-8859-1' and charset in charset_white_list:
				return str(data, charset, 'ignore')
		
		return str(data, 'utf-8', 'ignore')

	def parse_headers(self, data):
		headers = {}
		lines = data.split('\r\n')
		for _ in lines:
			pos = _.find(':')
			if pos > 0:
				headers[_[:pos].lower()] = _[pos+1:].strip()
		return headers

	def send_msg(self, data):
		result = json.dumps(data)
		if self.debug:
			print(result)
		if len(self.work_queue) >= self.max_queue_size*0.95:
			self.work_queue.clear()
		self.work_queue.append(result)