#!/usr/bin/python

import sys, os, argparse, socket, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def remoteExecute(pkt):
	return

def stopfilter(pkt):
	if ARP in pkt:
		return False
	return True

def main():
	cmdParser = argparse.ArgumentParser(description="8505A3-PortKnock Client")
	cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
	cmdParser.add_argument('-s','--srcIp',dest='srcIp', help='Source address of the host thats sending.', required=True)
	cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
	args = cmdParser.parse_args();


	while 1:
		payload = raw_input("Some input please: ")
		pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=random.randint(25089, 49151))/payload
		send(pkt)
		sniff(filter="udp and (src port " + args.dstPort + " and src " + args.dstIp + ")", prn=remoteExecute, stop_filter=stopfilter)

if __name__ == '__main__':
	main()
