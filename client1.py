#!/usr/bin/python

import sys, os, argparse, socket, logging, base64
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from Crypto.Cipher import AES

SECRET_KEY = '0123456789abcdef'

def AesEncrypt(plainText):
	cipher = AES.new(SECRET_KEY)
	paddedPlainText = str(plainText) + (((AES.block_size - len(str(plainText))) % AES.block_size) *"\0")
	cipherTxt = base64.b64encode(cipher.encrypt(paddedPlainText))
	return cipherTxt

def AesDecrypt(cipherTxt):
	secret = AES.new(SECRET_KEY)
	plainText = secret.decrypt(base64.b64encode(cipherTxt))
	unpaddedPlainText = plainText.rstrip("\0")
	return unpaddedPlainText

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
		pkt = IP(dst=args.dstIp, src=args.srcIp)/UDP(dport=int(args.dstPort), sport=8000)/AesEncrypt(payload)
		send(pkt)
		sniff(filter="udp and (src port " + args.dstPort + " and src " + args.dstIp + ")", stop_filter=stopfilter)

if __name__ == '__main__':
	main()
