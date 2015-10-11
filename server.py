import sys
from scapy.all import *
import argparse

secret_messageByteArray = [""];
secret_message = "";
character_index = 0;
BYTE_SIZE = 8;
bit_index = 0;

#set command line arguments
cmdParser = argparse.ArgumentParser(description="8505A1-CovertChannel Client")
cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
args = cmdParser.parse_args();

#Resets all the global variables
def globalReset():
    global secret_messageByteArray;
    global character_index;
    global bit_index;
    global secret_message;

    secret_messageByteArray = [""]
    character_index = 0;
    bit_index = 0;
    secret_message = "";


#Look for the specific IP addresses for the covert traffic
def parse(pkt):
    global secret_messageByteArray;
    global character_index;
    global BYTE_SIZE;
    global bit_index;
    global secret_message;


    
    # Analyze the source port for every packet,
    # Source ports less than 25088 equate to 0.
    # Source ports greater than 25088 equate to 1.
    # Source ports equaling 25088 signifies all packets were sent.
    if (pkt["TCP"].sport < 25088 ):
        bit = 0;
    elif (pkt["TCP"].sport > 25088 ):
        bit = 1;
    elif (pkt["TCP"].sport == 25088):
        print("\nComplete Message: " + secret_message)
        print "\n" + str(secret_messageByteArray)
        globalReset()
        return

    print "Received " + `1` + " packets."
    print "Source Port" + pkt["TCP"].sport
    print "."

    #Append the bit to the n'th element in secret_messageByteArray. n == character_index.
    secret_messageByteArray[character_index] += `bit`;
    bit_index+=1;

    #Since a single character can be represented by 1 byte, and 1 byte equals 8 bits, decode
    # the character once 8 bits have been sent.
    if(bit_index == BYTE_SIZE):
        #Append the decoded character to secret_message.
        secret_message += str(chr(int(secret_messageByteArray[character_index], 2)))
        print "\nMessage Received: " + secret_message + "\n"
        secret_messageByteArray.append("");
        #increment character_index, because the next set of 8 bits will represent the 
        # next character
        character_index+=1;
        bit_index = 0;

if __name__ == '__main__':
    sniff(filter="dst port " + args.dstPort + " and dst " + args.dstIp, prn=parse)
