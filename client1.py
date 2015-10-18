#!/usr/bin/python

import sys, os, argparse, socket, logging, base64
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

MASTER_KEY = '12345678901234567890123456789012'

def encrypt(data):
  secret = AES.new(MASTER_KEY)
  tagString = str(data) + (AES.block_size - len(str(data)) % AES.block_size) * "\0"
  cipherText = base64.b64encode(secret.encrypt(tagString))
  return cipherText

def decrypt(encryptedData):
  secret = AES.new(MASTER_KEY)
  rawDecrypted = secret.decrypt(base64.b64decode(encryptedData))
  data = rawDecrypted.rstrip("\0")
  return data

def stopfilter(pkt):
	if ARP in pkt:
		return False
	if Raw in pkt and UDP in pkt:
		print pkt['Raw'].load
		return True

def main():
	cmdParser = argparse.ArgumentParser(description="8505A3-PortKnock Client")
	cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
	cmdParser.add_argument('-s','--srcIp',dest='srcIp', help='Source address of the host thats sending.', required=True)
	cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
	args = cmdParser.parse_args();


	while 1:
		payload = raw_input("Some input please: ")
		pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=8000)/encrypt(payload)
		send(pkt)
		sniff(filter="udp and (src port " + args.dstPort + " and src " + args.dstIp + ")", stop_filter=stopfilter)

if __name__ == '__main__':
	main()
