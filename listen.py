import socket
import os
import struct
import select

# host to listen on
host = "192.168.1.12"
#host = ""
# create a raw socket and bind it to the public interface
sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))
sniffer.bind((host, 0))


# we want the IP headers included in the capture
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# if we're using Windows, we need to send an IOCTL
# to set up promiscuous mode
if os.name == "nt":
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# read in a single packet

while True:
	whatReady = select.select([sniffer], [], [], 2)
	recPacket, addr = sniffer.recvfrom(1024)#65565)
	icmpHeader = recPacket[20:28]
	icmpData = recPacket[28:]
	type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmpHeader)
	
	print type
	print code
	print checksum
	print packetID
	print sequence
	print icmpData
	print addr
		
	if(raw_input("Continue?") == "no"):
		break
sniffer.close()
# if we're using Windows, turn off promiscuous mode

#if os.name == "nt":
#	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
