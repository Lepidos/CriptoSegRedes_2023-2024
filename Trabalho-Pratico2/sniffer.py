from scapy.all import *

def print_pkt(pkt):
	pkt.show()

pkt = sniff(iface='lo', filter='tcp and port 7777', prn=print_pkt)
