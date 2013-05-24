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
