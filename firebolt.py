#!/usr/bin/env python
__description__ = 'Firebolt - Hunting tool to identify unknown binaries on a system. '
__author__ = 'Anibal Rodriguez'
__version__ = '0.2'

import os, sys
from optparse import OptionParser
from tsv_parse import tsvparser
import wash_hashes
from es_import import bulk_send

def proc_core(filename):
    wash_hashes.start_washing('targets.hashes')
    print "[-] Chunking ouput file to manageable sizes for VT"
    wash_hashes.split_file('rem_3.out')
    print "[-] Aurors are checking virustotal...please wait\n"
    q = 'virustotal/vt_query.py %s' % filename
    os.system(q)
    complete = bulk_send('reports/report.csv')
    
    # CLEAN UP REPORTS DIRECTORY
    if complete:
        os.remove('reports/report.txt')
        os.remove('reports/report.csv')
	

def main():
    parser = OptionParser(usage='usage: %prog [options] [filename | image_name]\n' + __description__)
    parser.add_option("-t", "--tsv", action='store_true', default=False, help="TSV file output from X-Ways Forensic Tool")
    parser.add_option("-e", "--e01", action='store_true', default=False, help="Use ewfmount to mount E0 Evidence Files")
    (options, args) = parser.parse_args()

    if len(args) == 0:
        print "[!] Please provide something to process\n\n"
        parser.print_help()
        sys.exit()

    # Sort args
    img_file = args[0]

    if options.tsv:
        tsvparser(args[0])
        filename_host = os.path.split(args[0])[1]
        proc_core(filename_host)

    # Dont trust the user force E01 Check
    if img_file.endswith('.E01'):
        options.e01 = True

if __name__ == "__main__":
    main()
