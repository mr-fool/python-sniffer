#Packet sniffer in Python

import socket, sys
from struct import *

#convert a string of a 6 characters of ethernet address into a dash separated
#hex string

def eth_addr (a):
    b = "%.2x: %.2x %.2x: %.2x %.2x: %.2x" % ( ord( chr( a[0] ) ), ord( chr( a[1] ) ), ord( chr( a[2] ) ),  ord( chr( a[3] ) ) , ord( chr( a[4] ) ), ord( chr( a[5] ) ) )
    return b

#create a AF_PACKET type raw socket

try: 
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

except socket.error as msg:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + 'Message ' + msg[1])
    sys.exit()

#receive a packet 
while True:
    packet = s.recvfrom(65565)

    #packet string from tuple
    packet = packet[0]

    #parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sh', eth_header)
    eth_protocol = socket.ntohs(eth[2])
    print ('Destination MAC : ' + str ( eth_addr(packet [0:6]) ) + ' Source MAC :' + str( eth_addr(packet[6:12]) )+ ' Protocol : ' + str(eth_protocol))

