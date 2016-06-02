#!/usr/bin/env python
import subprocess, re
import os
from chunker import split_file

def wash_nsrl(hashfile):
    cmd = "hfind -f %s ./rc_hashes/rc_total_hashes.txt > rc.hashes" % hashfile
    subprocess.call(cmd, shell=True)

    with open('rc.hashes') as f:
        with open('rem_1.out', 'w') as fout:
            for line in f:
                if re.findall(r'Not Found', line):
                    hashval = line.split('\t')[0]
                    fout.write(hashval +'\n')

def wash_intel(hashfile):
    cmd = "hfind -f %s ./gold_hashes/intel-windows-gold.db > intel.hashes" % hashfile
    subprocess.call(cmd, shell=True)

    with open('intel.hashes') as f:
        with open('rem_2.out', 'w') as fout:
            for line in f:
                if re.findall(r'Not Found', line):
                    hashval = line.split('\t')[0]
                    fout.write(hashval +'\n')

def wash_rolling_wlist(hashfile):
    cmd = "hfind -f %s ./rolling_hashes/rolling_wlist.db > rolling.hashes" % hashfile
    subprocess.call(cmd, shell=True)

    with open('rolling.hashes') as f:
        with open('rem_3.out', 'w') as fout:
            for line in f:
                if re.findall(r'Not Found', line):
                    hashval = line.split('\t')[0]
                    fout.write(hashval +'\n')

#Wash Through RC HASHES
def start_washing(filetowash):
    if os.path.exists(filetowash):
        print "[-] Washing through NSRL RC hashes."
        wash_nsrl(filetowash)

        print "[-] Washing throught Intel Gold database"
        wash_intel('rem_1.out')

        print "[-] Washing throught Intel Rolling database"
        wash_rolling_wlist('rem_2.out')

        print "[-] Remaining hashes will be sent to VirusTotal"
        print "[-] File: rem_3.out"


        #REMOVE files
        os.remove('rc.hashes')
        os.remove('intel.hashes')
        os.remove('rolling.hashes')
        os.remove('rem_1.out')
        os.remove('rem_2.out')
    else:
        print '[!] Cannot do magic. File not found: ', filetowash
