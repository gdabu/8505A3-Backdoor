#!/usr/bin/python

import sys, os, argparse, socket, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def knock(host, ports):
	host = args.destIp
	ports = []
	for port in args.ports:
		ports.append(port)
	for i in ports:
		pkt = IP(dst=host)/TCP(sport=int(i), dport=RandNum(0,65355), window=4096)
		send(pkt)

def main():
	knock(args.destIp, args.ports)

if __name__ == '__main__':
	try:
		main()
	except KeyboardInterrupt:
		print 'Exiting..'
