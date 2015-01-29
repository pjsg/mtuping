#!/usr/bin/env python

from scapy.all import *
import sys

dest = sys.argv[1]

debug.recv[:] = []
conf.debug_match = 1

z = sr1(IPv6(dst=dest)/ICMPv6EchoRequest(data='P' * 1400), verbose=0, timeout=1)

if not z:
	print "No response"
	send(IPv6(dst=dest)/ICMPv6PacketTooBig(mtu=1281)/IPv6(src=dest))
else:
	# Now send the PTB

	send(IPv6(dst=dest)/ICMPv6PacketTooBig(mtu=1280)/z)

# Now send ping again

debug.recv[:] = []

z1 = sr1(IPv6(dst=dest)/ICMPv6EchoRequest(data='Q' * 1400), verbose=0, timeout=1)

if z1:
	print "PTB seems to have been ignored"
else:
	# Search the packet chain for the ICMP
	for resp in debug.recv:
	    if IPv6 in resp:
		v6 = resp[IPv6]
		print resp.summary()
