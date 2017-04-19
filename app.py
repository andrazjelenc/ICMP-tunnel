import dpkt
import os
import random
import select
import socket
import struct
import sys
import threading

def send_message(inputData):
	splitted = inputData.split(' ', 1)
	
	dest = socket.gethostbyname(splitted[0]) #destination IP addr
	msg = splitted[1].encode("utf-8") #message
	
	#dpkt object
	echo = dpkt.icmp.ICMP.Echo()
	echo.id = random.randint(0, 0xffff)
	echo.seq = random.randint(0, 0xffff)
	echo.data = msg

	icmp = dpkt.icmp.ICMP()
	icmp.type = dpkt.icmp.ICMP_ECHO 
	icmp.data = echo

	#open socket
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_ICMP)
	
	#bind to public interface (ip, port) and send packet
	s.bind((INTERFACE, 0)) 
	s.sendto(str(icmp), (dest, 1))
	

def receive_message(sniffer):
	whatReady = select.select([sniffer], [], [], 2)
	recPacket, addr = sniffer.recvfrom(1024)
	icmpHeader = recPacket[20:28]
	icmpData = recPacket[28:]
	type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
	
	#filter out our own packets
	if(addr[0] == INTERFACE): 
		return ""
	
	msgData = icmpData.decode("utf-8")
	message = addr[0] + ": " + msgData
	return message


def message_receiver():
	#open socket and bind it to our interface
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
	sniffer.bind((INTERFACE, 0))
	
	#capture headers too
	sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

	#on WinOS we need to enable promisc mode
	if os.name == "nt":
		sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	while True:
		msg_received = receive_message(sniffer)
		if len(msg_received) > 0: # ce obstaja sporocilo
			print("[Received] " + msg_received) # izpisi


if __name__ == "__main__":
	global INTERFACE
	INTERFACE = "192.168.1.10" #default interface, used if input empty

	newIface = raw_input("Enter interface ip: ")
	if(len(newIface) > 0):
		INTERFACE = newIface
	
	#start listening on interface
	thread = threading.Thread(target=message_receiver)
	thread.daemon = True
	thread.start()

	#send message (format: "destination message")
	while True:
		try:
			msg_send = raw_input()
			send_message(msg_send)
		except KeyboardInterrupt:
			sys.exit()
