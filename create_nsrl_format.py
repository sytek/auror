#!/usr/bin/env python
import os
import shutil

with open('virustotal/session_whitelist.txt') as f:
	with open('rolling_hashes/new_wlist.txt', 'w') as f2:
		#f2.write('"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"\n')
		for sha1 in f:
			f2.write('"'+sha1.rstrip('\n')+'","00000000000000000000000000000000","00000000","INTEL-Rolling",0,0,"",""\n')


#PYTHON EQUIV OF CAT. USED TO CONCATENATE BOTH FILES
with open('rolling_hashes/rolling_wlist.db', 'a') as outfile:
    with open('rolling_hashes/new_wlist.txt') as infile:
        for line in infile:
            outfile.write(line)

os.remove('virustotal/session_whitelist.txt')
os.remove('rolling_hashes/new_wlist.txt')
