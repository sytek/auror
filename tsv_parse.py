#!/usr/bin/env python
import csv, codecs
import re, os
from io import BytesIO
from StringIO import StringIO as BytesIO

def tsvparser(tsv_in):
    # File from X-Ways in TSV format
    fs_out = 'filesystem.dobby'
    int_hashes = 'not-clean.hashes'
    outfilename = 'targets.hashes'

    # Convert to Dobby File
    with open(tsv_in, 'rb') as binf:
        c = binf.read().decode('utf-16').encode('utf-8')
    with open(fs_out, 'w') as f:
        for line in csv.reader(BytesIO(c), delimiter="\t"):
            f.write("%s ; %s ; %s \n" % (line[2],line[1],line[0]))

    # Extract Target Files and Hashes from Dobby file. Send to FULL.HASHES
    with open(fs_out) as f:
        with open(int_hashes, 'w') as fout:
            for line in f:
                if re.findall(r'[EecC][XxoO][EemM].$', line):
                    hashval = line.split(';')[0].rstrip(' ')
                    fout.write(hashval +'\n')
                #elif re.findall(r'[sSdD][yYlL][sSlL].$', line):
                #    hashval = line.split(';')[0].rstrip(' ')
                #    fout.write(hashval +'\n')

    # UNIQUE equivalent
    lines_seen = set() # holds lines already seen
    outfile = open(outfilename, "w")
    for line in open(int_hashes, "r"):
        if line not in lines_seen and line != "\n": # not a duplicate
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()

    #remove intermediary hashlist
    os.remove('not-clean.hashes')
