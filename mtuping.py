#!/usr/bin/env python

from scapy.all import *
import sys
import socket

dest = sys.argv[1]

debug.recv[:] = []
conf.debug_match = 1

ip = IPv6(dst=dest)
dstaddr = inet_ntop(socket.AF_INET6, ip.dst.net)

z = sr1(ip/ICMPv6EchoRequest(data='P' * 1400), verbose=0, timeout=1)

if not z:
	print "No response"
	for resp in debug.recv:
	    if IPv6 in resp:
		v6 = resp[IPv6]
		if v6.src == dstaddr:
			print "Packet length ", len(str(resp)), ": ", resp.summary()
	send(ip/ICMPv6PacketTooBig(mtu=1281)/IPv6(src=dest))
else:
	# Now send the PTB
	zb = str(z)

	send(ip/ICMPv6PacketTooBig(mtu=1280)/zb[0:512])

# Now send ping again

debug.recv[:] = []

z1 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1400), verbose=0, timeout=1)

if z1:
	print "PTB seems to have been ignored"
else:
	# Search the packet chain for the ICMP
	for resp in debug.recv:
	    if IPv6 in resp:
		v6 = resp[IPv6]
		if v6.src == dstaddr:
			print "Packet length ", len(str(resp)), ": ", resp.summary()
