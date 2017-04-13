import dpkt
import socket
import random


def send_ping(dest, message, timeout = 2):
	#translate hostname to IPv4 format
	dest = socket.gethostbyname(dest)		
	
	
	echo = dpkt.icmp.ICMP.Echo()
	#set some random values for id and seq number
	echo.id = random.randint(0, 0xffff)
	echo.seq = random.randint(0, 0xffff)
	#set our message as data
	echo.data = message

	print `echo`
	#create icmp packet
	icmp = dpkt.icmp.ICMP()
	print `icmp`
	icmp.type = dpkt.icmp.ICMP_ECHO 
	print `icmp`
	icmp.data = echo
	print `icmp`

	#open socket
	s = socket.socket(socket.AF_INET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_ICMP)
	#bind to public interface (ip, port) and send packet
	s.bind(("193.2.178.30", 0)) 
	s.sendto(str(icmp), (dest, 1))

if __name__ == "__main__":
	send_ping("www.google.com", "a TI JE IME")
