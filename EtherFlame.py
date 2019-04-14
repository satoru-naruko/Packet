#!/usr/bin/env python

import socket


class EtherFlame:

    def __init__(self, src_mac_addr, dst_mac_addr, ethertype):
        self.src_mac_addr = src_mac_addr
        self.dst_mac_addr = dst_mac_addr
        self.ethertype = ethertype

    def string(self):
        return self.dst_mac_addr + self.src_mac_addr + self.ethertype


if __name__ == "__main__":

    rawSocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    rawSocket.bind(("eth1", 0))

    src_mac = "\x11\x11\x11\x11\x11\x11"
    dst_mac = "\x22\x22\x22\x22\x22\x22"
    ether_type = "\x08\x00"

    flame = EtherFlame(src_mac, dst_mac, ether_type)

    rawSocket.send(flame.string())
