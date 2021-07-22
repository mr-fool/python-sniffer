import socket
import select
 
#create raw packet object (sniffer)
sniffer6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
sniffer4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
 
 
#get a single packet
 
while True:
    ready, _, _ = select.select([sniffer4, sniffer6], [], [])
    if ready:
        print ( ready[0].recvfrom(65535) )
    