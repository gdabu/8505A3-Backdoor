from scapy.all import *
import argparse
import time

#set command line arguments
cmdParser = argparse.ArgumentParser(description="8505A1-CovertChannel Client")
cmdParser.add_argument('-d','--dstIp',dest='dstIp', help='Destination address of the host to send the message to.', required=True)
cmdParser.add_argument('-p','--dstPort',dest='dstPort', help='Destination port of the host to send the message to.', required=True)
cmdParser.add_argument('-w','--waitTime',dest='waitTime', help='The maximum wait time (milliseconds) in between sent packets.', required=True)
args = cmdParser.parse_args();

def main():

	# 1. Initialize constant packet variables.
	craftedPkt = IP()/TCP();
	craftedPkt["TCP"].dport = int(args.dstPort);
	craftedPkt["IP"].dst = args.dstIp;

	craftedPkt["TCP"].sport = 25089;
	send(craftedPkt)
	craftedPkt["TCP"].sport = 90020;
	send(craftedPkt)
	craftedPkt["TCP"].sport = 40396;
	send(craftedPkt)

	

	
	# # 2. Prompt user for secret message.
	# secret_message = raw_input("Enter your secret message: ")
	# print "Secret Message: " + secret_message

	# # 3. Morse Code Conversion.
	# # Convert every character in the message into bytes, and store it into secret_messageByteArray.
	# # Every value in secret_messageByteArray will be a string equaling the byte value for each 
	# #  character in the secret message.
	# secret_messageByteArray = [bin(ord(ch))[2:].zfill(8) for ch in secret_message]
	# print "Secret Message in Bytes: " + str(secret_messageByteArray)
	
	# # 4. Send Secret Message.
	# #Send a packet for each bit of each byte in secret_messageByteArray.
	# #if the bit is 0, send a packet with a random source port in between 1025, and 25087.
	# #if the bit is 1, send a packet with a random source port in between 25089, and 49151.
	# for byte in secret_messageByteArray:
	#     for bit in byte:
	#         if (bit == '0'):
	#             randPort = random.randint(1025, 25087);
	#             craftedPkt["TCP"].sport = randPort;
	#         else:
	#             randPort = random.randint(25089, 49151);
	#             craftedPkt["TCP"].sport = randPort;

	#         #sleep for a random time before sending a packet.
	#         time.sleep(random.uniform(1/1000, int(args.waitTime)/1000))
	#         print "Source Port: " + `craftedPkt["TCP"].sport`
	#         #spoof source ip address.
	#         send(craftedPkt)

	# # 5. Send message completion signal.
	# #After the entire message has been sent, send a packet with a source port of 25088.
	# craftedPkt["TCP"].sport = 25088;
	# send(craftedPkt);

	print "\nMessage Sent."


if __name__ == '__main__':
	main();
