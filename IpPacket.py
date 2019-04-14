#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ver3.6.6.6 で動作確認

import socket
import struct


class IpPacket:

	def __init__(self):
		# ipバージョン 4 -> ２進数で 0100
		self.version = 0b0100
		# ipヘッダの長さ ほとんどの場合２進数で 0101
		self.hl = 0b0101
		# tos ( type of service ) qosの設定するときはここにセット
		self.tos = 0
		# 識別子 (Identification)
		self.id = 0 
		# フラグ
		# 1bit目: 未定義のため常に0。
		# 2bit目: DF bit(Don't Fragment)。0=フラグメントを許可 1=フラグメントを禁止
		# 3bit目: MF bit(More Fragment)。0=後続にフラグメントデータ無し、1=後続にフラグメントデータ有り
		self.flags = 0b010 
		# フラグメントのオフセット フラグの2bit目が1なら０となる
		self.offset = 0
		# TTL (time to live) ルーティングされるたびに１減る　０になるとICMPで通知される 
		self.ttl = 255
		# プロトコル
		self.protocol = 255
		# チェックサム
		self.checksum = 0
		# 送信元ipアドレス
		self.src_ip = b"\x7f\x00\x00\x01"
		# 宛先ipアドレス
		self.dst_ip = b"\x7f\x00\x00\x01"
		# IPパケットのデータ
		self.data = b""
	
	def get_addr(self, name):
		return socket.inet_aton(socket.gethostbyname(name))
	
	def get_checksum(self, data):
		checksum = 0
		data_len = len(data)
		# IPヘッダからの情報で作られる擬似ヘッダとUDPヘッダとデータを長さが
		# 2オクテットの倍数になるように（必要なら）値がゼロのオクテットでパディング
		if (data_len%2) == 1:
			data_len += 1
			data += struct.pack('!B', 0)
		
		# 各2オクテットの1の補数の総和を求める
		for i in range(0, len(data), 2):
			# 1の補数演算で足しあわせる
			# 補数とは　数 x とその補数 x' は、足すと 0xFFFF になる
			# 0x0001 の「1の補数」は、0xFFFE
			w = (data[i] << 8) + (data[i + 1])
			checksum += w
		checksum = (checksum >> 16) + (checksum & 0xFFFF)
		# その合計を1の補数化する
		checksum = ~checksum & 0xFFFF
		return checksum		
	
	def set_src(self, name):
		self.src_ip = self.get_addr(name)
	
	def set_dst(self, name):
		self.dst_ip = self.get_addr(name)
	
	def payload(self):
		pack = struct.pack
		length = self.hl*4+len(self.data)
		result = pack('B', (self.version << 4)+self.hl)
		result += pack('B',self.tos)
		result += pack(">H", length)
		result += pack(">H", self.id)
		result += pack(">H", (self.flags << 13)+self.offset)
		result += pack("B",self.ttl)
		result += pack("B",self.protocol)
		result += pack(">H", self.get_checksum(result+b"\x00\x00"+self.src_ip+self.dst_ip))
		result += self.src_ip+self.dst_ip+self.data
		return result


def udppacket(data, dst_addr, src_addr):
	p = IpPacket()

	# udp(17)
	p.protocol = 0x11 

	# IPアドレスをセット
	p.set_src(src_addr[0])
	p.set_dst(dst_addr[0])

	'''
	udpヘッダ
	0      7 8     15 16    23 24    31 
	+--------+--------+--------+--------+
	|      Src        |    Destination  |
	|      Port       |       Port      |
	+--------+--------+--------+--------+
	|      Length     |     Checksum    |
	+--------+--------+--------+--------+
	|      data packet                  |
	+-----------------------------------+
	'''
	# port番号
	src_port = src_addr[1]
	dst_port = dst_addr[1]
	
	# udp ヘッダに値をセット
	pack = struct.pack
	udp_header = pack(">HHH", src_port, dst_port, len(data)+8)
	
	# UDPヘッダサイズ(8固定) + データサイズ
	udp_length = 8 + len(data)

	# チェックサム用擬似ヘッダ(pseudo_header)
	pseudo_header = p.src_ip + p.dst_ip + struct.pack('!BBH', 0, p.protocol, udp_length)
	
	# チェックサムを算出
	checksum = p.get_checksum(pseudo_header + udp_header + data)

	# udpヘッダにチェックサムをセット
	udp_header = struct.pack('!4H', src_port, dst_port, udp_length, checksum)

	# ipパケットのペイロードにuddパケットをセット
	p.data = udp_header+data

	return p.payload()


def rtppacket(data, payload_type, sequence_number, timestamp, ssrc):
	
	version = 0b10
	padding = 0
	extension_header = 0
	csrc_count = 0
	marker = 0

	pack = struct.pack
	rtp_header = pack('B', (version << 6)+(padding << 5)+(extension_header << 4)+(csrc_count & 0xff))
	rtp_header += pack('B', (marker << 7)+(payload_type & 0x7f))

	# シーケンス番号
	rtp_header += pack('B', ((sequence_number & 0xff00) >> 8))
	rtp_header += pack('B', (sequence_number & 0x00ff))

	# タイムスタンプ
	rtp_header += pack('B', ((timestamp & 0xff000000) >> 24))
	rtp_header += pack('B', ((timestamp & 0x00ff0000) >> 16))
	rtp_header += pack('B', ((timestamp & 0x0000ff00) >> 8))
	rtp_header += pack('B', (timestamp & 0x000000ff))

	# ssrc
	rtp_header += pack('B', ((ssrc & 0xff000000) >> 24))
	rtp_header += pack('B', ((ssrc & 0x00ff0000) >> 16))
	rtp_header += pack('B', ((ssrc & 0x0000ff00) >> 8))
	rtp_header += pack('B', (ssrc & 0x000000ff))

	return rtp_header + data


if __name__ == "__main__":

	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
	s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	
	for i in range(1, 100, 1):
		rtp = rtppacket(bytes('111222333', encoding='utf-8', errors='replace'), 9, i, 20 * i, 163461)
		p = udppacket(rtp, ("192.168.0.21", 1234), ("192.168.0.9", 11111))
		s.sendto(p, ("192.168.0.21", 0))
