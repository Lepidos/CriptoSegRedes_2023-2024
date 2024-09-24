from scapy.all import *
#a = IP()
a = IP(src='172.17.0.1', dst='8.8.8.8')
#a.src = '192.168.127.128'
#a.dst = '8.8.8.8'
#a.dst = '192.168.1.254'
b = ICMP()
#a.timeout = '3'
p = a/b

#p = IP(src='192.168.127.128', dst='8.8.8.8') / ICMP(type="echo-request", code=0)

send(p)
