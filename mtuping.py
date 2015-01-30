#!/usr/bin/env python
"""Usage: mtuping.py [--mtu mtu] <host>

 -h --help          Show this
 -m mtu, --mtu=mtu  The MTU to simulate [default: 1280]    

"""

from docopt import docopt
from scapy.all import *
import sys
import socket
import random

def print_matching(dstaddr, packets):
	for resp in packets:
	    if IPv6 in resp:
		v6 = resp[IPv6]
		if v6.src == dstaddr:
			print "Packet length ", len(str(resp)), ": ", resp.summary()


def doping(args):
	dest = args['<host>']
	mtu = int(args['--mtu'])
	debug.recv[:] = []
	conf.debug_match = 1

        id = random.randint(0, 65535)
	seq = 0

	ip = IPv6(dst=dest)
	dstaddr = inet_ntop(socket.AF_INET6, ip.dst.net)

	debug.recv[:] = []

	z3 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1200, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if z3:
		print "Ping size 1200 returned"
	else:
		print "Small ping failed"

	z = sr1(ip/ICMPv6EchoRequest(data='P' * 1400, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if not z:
		print "No response"
		print_matching(dstaddr, debug.recv)

		send(ip/ICMPv6PacketTooBig(mtu=mtu)/IPv6(src=dest))
	else:
		print "Packet size 1400 returned. Sending PTB"
		# Now send the PTB
		zb = str(z)

		send(ip/ICMPv6PacketTooBig(mtu=mtu)/zb[0:512])

	# Now send ping again

	debug.recv[:] = []

	z1 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1400, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if z1:
		print "PTB seems to have been ignored"
	else:
		# Search the packet chain for the ICMP
		print "No complete packet returned"
		print_matching(dstaddr, debug.recv)

	debug.recv[:] = []

	z2 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1200, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if z2:
		print "Ping size 1200 returned"
	else:
		print "Small ping failed"


if __name__ == '__main__':
    arguments = docopt(__doc__, version='mtuping 0.1')
    doping(arguments)
