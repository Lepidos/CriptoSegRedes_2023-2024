from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='docker0', filter='arp', prn=print_pkt) # 2.1
#pkt = sniff(iface=iface, filter='tcp and dst port 80', prn=print_pkt) # 2.2
#pkt = sniff(iface=iface, prn=print_pkt) # 2.3
