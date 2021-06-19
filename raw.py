import socket
import select
 
#create raw packet object (sniffer)
sniffer6 = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
sniffer4 = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
 
#bind it to a host
sniffer6.bind(('::', 0))
sniffer4.bind(('0.0.0.0', 0))
 
#make sure that IP header is included also 
sniffer6.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL,1)
sniffer4.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL,1)
 
# Make it non-blocking
sniffer4.setblocking(False)
sniffer6.setblocking(False)
 
print ("sniffer is listening for incoming connections")
 
#get a single packet
 
while True:
    ready, _, _ = select.select([sniffer4, sniffer6], [], [])
    if ready:
        print ( ready[0].recvfrom(65535) )
        break

