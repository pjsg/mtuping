#!/usr/bin/env python
"""Usage: mtuping.py [--mtu mtu] [--verbose] <host>

 -h --help          Show this
 -m mtu, --mtu=mtu  The MTU to simulate [default: 1280]    
 -v --verbose       Show verbose information

"""

from docopt import docopt
from scapy.all import *
import sys
import socket
import random
import re
from collections import OrderedDict

explanations = OrderedDict([
		( 'NN00N', 'Unreachable.' ),
		( '.Y22Y', 'Unable to test. Returns fragments without prompting.' ),
		( '.Y00Y', 'Unable to test. Doesn\'t respond to large echo requests.' ),
		( '.YY0Y', 'Site does not generate fragmented echo replies. Does change behavior after receiving PTB.' ),
		( '..Y2.', 'Site generated fragmented echo reply after receving PTB. Success!' ),
		( '.YYYY', 'Site ignored PTB message. This will cause problems.' ),
	])

def print_matching(dstaddr, packets, verbose=False):
	result = 0
	for resp in packets:
	    if IPv6 in resp:
		v6 = resp[IPv6]
		if v6.src == dstaddr:
		        result = result + 1
			if verbose:
			    print "Packet length ", len(str(resp)), ": ", resp.summary()

	return str(result)


def doping(args):
	dest = args['<host>']
	mtu = int(args['--mtu'])
	verbose = args['--verbose']
	debug.recv[:] = []
	conf.debug_match = 1

        id = random.randint(0, 65535)
	seq = 0

	dest = Net6(dest)
	ip = IPv6(dst=dest)
	dstaddr = inet_ntop(socket.AF_INET6, ip.dst.net)

	debug.recv[:] = []

	if verbose:
		print "Testing ", dstaddr

	status = ''

	z3 = sr1(ip/ICMPv6EchoRequest(data='Q' * 16, id=id, seq=seq), verbose=0, timeout=1)
	seq = seq + 1
	if z3:
		if verbose:
		    print "Ping size 16 returned"
		status = status + 'Y'
	else:
		if verbose:
		    print "Very small ping failed"
		status = status + 'N'


	z3 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1200, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if z3:
		if verbose:
		    print "Ping size 1200 returned"
		status = status + 'Y'
	else:
		if verbose:
		    print "Small ping failed"
		status = status + 'N'

	z = sr1(ip/ICMPv6EchoRequest(data='P' * 1400, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if not z:
		if verbose:
		    print "No response"
		status = status + print_matching(dstaddr, debug.recv, verbose)

		send(ip/ICMPv6PacketTooBig(mtu=mtu)/IPv6(src=dest), verbose=0)
	else:
		status = status + 'Y'
		if verbose:
		    print "Packet size 1400 returned. Sending PTB"
		# Now send the PTB
		zb = str(z)

		send(ip/ICMPv6PacketTooBig(mtu=mtu)/zb[0:512], verbose=0)

	# Now send ping again

	debug.recv[:] = []

	z1 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1400, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if z1:
		status = status + 'Y'
		if verbose:
		    print "PTB seems to have been ignored"
	else:
		# Search the packet chain for the ICMP
		if verbose:
		    print "No complete packet returned"
		status = status + print_matching(dstaddr, debug.recv, verbose)

	debug.recv[:] = []

	z2 = sr1(ip/ICMPv6EchoRequest(data='Q' * 1200, id=id, seq=seq), verbose=0, timeout=1)
	seq += 1

	if z2:
		status = status + 'Y'
		if verbose:
		    print "Ping size 1200 returned"
	else:
		status = status + 'N'
		if verbose:
		    print "Small ping failed"

	matched = False
	for pattern in explanations:
		if re.match(pattern, status):
			print "%s: %s" % (dstaddr, explanations[pattern])
			matched = True
			break

	if not matched:
		print "%s: Unknown (%s)" % (dstaddr, status)

if __name__ == '__main__':
    arguments = docopt(__doc__, version='mtuping 0.1')
    doping(arguments)
