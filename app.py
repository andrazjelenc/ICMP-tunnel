import socket
import struct
import sys
import threading
import random
import os
import subprocess
import select

#todo: differnet colors for command output, standar output...
#class bcolors:
#    HEADER = '\033[95m'
#    OKBLUE = '\033[94m'
#    OKGREEN = '\033[92m'
#    WARNING = '\033[93m'
#    FAIL = '\033[91m'
#    ENDC = '\033[0m'
#    BOLD = '\033[1m'
#    UNDERLINE = '\033[4m'

	
def run_cmd(command):
	#print "executing: " + command
	proc = subprocess.Popen('cmd.exe', stdin = subprocess.PIPE, stdout = subprocess.PIPE)
	stdout, stderr = proc.communicate(command+'\n')
	return stdout	#return output
	
def execution(source, command):
	output = run_cmd(command)
	if(len(output) > 0):
			#split output and remove header
			splittedOutput = output.split(command, 1)
			
			#remove last execPath line
			execPath = splittedOutput[0].split("\n")[-1];
			cOutput = splittedOutput[1]
			cOutput = cOutput.rsplit(execPath, 1)
			cOutput = cOutput[0]
			cOutput = cOutput.strip()
			
			#todo: add try catch for larger output
			send_message(source, "[CMD-Out] \n" + cOutput)
	
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

def send_message(dest, message):
	#splitted = inputData.split(' ', 1)
	try:
		dest = socket.gethostbyname(dest) #destination IP addr
		message = message#.encode("utf-8") #encoded message
		
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
	except Exception as inst:
		if(inst.args[0] == 11004):
			print "Unable to resolve destination IP"
		else:
			print inst.args
	

def receive_message(sniffer):
	whatReady = select.select([sniffer], [], [], 2)
	recPacket, addr = sniffer.recvfrom(65565)
	icmpHeader = recPacket[20:28]
	icmpData = recPacket[28:]
	type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
	
	source = addr[0]
	
	if(type == 0):
		type = "Reply"
	elif(type == 8):
		type = "Request"
	else:
		type = "Unknown("+type+")"
		
	msgData = icmpData#.decode("utf-8")
	
	#filter out our own packets
	if(source == INTERFACE): 
		return ""
	
	if EXECMODE == True and len(msgData) > 5 and msgData[:5] == "#run#" and type == "Request": #be carefull without that one
		execution(source, msgData[5:])
	
	return "[Received] [" + str(source) + "] [" + str(type) + "]: " + str(msgData)

def message_receiver():
	#open socket and bind it to our interface
	
	#todo: tukaj se se nekaj sesuva, lahko tudi v funkciji reveive_message
	try:
		print "Starting sniffer..."
		
		sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		sniffer.bind((INTERFACE, 0))
	
		#capture headers too
		sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

		#on WinOS we need to enable promisc mode
		if os.name == "nt":
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
		
		print "Sniffer started! Waiting..."
		
		while True:
			msg_received = receive_message(sniffer)
			if len(msg_received) > 0: # ce obstaja sporocilo
				print(msg_received) # izpisi
				
	except Exception as inst:
		if(inst.args[0] == 10049 or inst.args[0] == 11004 or inst.args[0] == 99):
			print "Unable to access local interface - bad IP"
		elif(inst.args[0] == 10013):
			print "Unable to access local interface - run as root"
		else:
			print inst.args
		
		if os.name == "nt":
			sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
			
		os._exit(1)

if __name__ == "__main__":
	global INTERFACE
	global EXECMODE
	
	#INTERFACE = "192.168.1.12" #default interface, used if input empty
	INTERFACE = "193.2.176.109"
	EXECMODE = False		#run commands in cmd (messages: #run#command)		
	
	newIface = raw_input("Enter interface ip: ")
	if(len(newIface) > 0):
		INTERFACE = newIface
	
	newExecMode = raw_input("Enable command execution (ExecMode)? [YES/any]")
	if(len(newExecMode) > 0 and newExecMode.strip() == "YES"):
		EXECMODE = True
	
	if(EXECMODE == True):
		print "Using interface IP: " + INTERFACE + " with ExecMode ENABLED!"
	else:
		print "Using interface IP: " + INTERFACE + " with ExecMode disabled!"
		
	
	#start listening on interface
	thread = threading.Thread(target=message_receiver)
	thread.daemon = True
	thread.start()
		
	#send message (format: "<destination> <message>")
	while True:
		try:
			msg_send = raw_input()
			parts = msg_send.split(' ', 1)
			send_message(parts[0], parts[1])
		except IndexError:
			print "[!]Input format is: <desination URL/IP> <message>"
		except KeyboardInterrupt:
			sys.exit()
