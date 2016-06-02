#!/usr/bin/env python
import simplejson, urllib, urllib2, traceback
import subprocess, os
import time

apt_count = 0
malware_count = 0
fp_count = 0
wlist_count = 0

def header():
	# Report Header
	with open('reports/report.txt', 'a') as f:
		f.write("Report Generated: " + time.strftime("%x at %X")+"\n")
		f.write(
				'''
		**************************************************************
		 _______ _____  ______ _______ ______   _____         _______
		 |______   |   |_____/ |______ |_____] |     | |         |
		 |       __|__ |    \_ |______ |_____] |_____| |_____    |
		                        Version 0.2
		**************************************************************
			''')
		f.write('\nHostname: n/a'+ '\n\n')

# ADD A HASH VALUE TO THE WHITELIST
def add_to_wlist(hashval):
	with open('session_whitelist.txt', 'a') as f:
		f.write(hashval + '\n')

# ADD SUSPECTED APT HASH TO REPORT
def add_to_report(hashval):
	with open('reports/report.txt', 'a') as f:
		cmd = 'grep %s filesystem.dobby' % hashval
		out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
		filepath = out.stdout.read()
		f.write("\n[!] DEMENTOR APT FOUND!  -- " + hashval + '\n')
		f.write(filepath)

## CHECK IF FILE REPORT.TXT ALREADY EXISTS
if os.path.exists('reports/report.txt') is False:
	header()


# MERGE REMANING HASHES & CREATE CSV LIST AND SAVE TO VARIABLE: batch_hashes
path = 'virustotal/chunker/'
for filename in os.listdir(path):
	with open(path+filename) as f:
		batch_hashes = ', '.join(line.strip() for line in f)

	parameters = {"resource": batch_hashes,
				   "apikey" : "34b8488b2ef1efe5e901684f838cb982ba9c7a1684ecf5e0af9569ab062c5f8a"
	}

	# CREATE WEB REQUEST TO VIRUSTOTAL
	try:
		url = "https://www.virustotal.com/vtapi/v2/file/report"
		data = urllib.urlencode(parameters)
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req)
		json_res = response.read()

		parsed_json = simplejson.loads(json_res)

		x = len(parsed_json) - 1
		while x >= 0:
			rcode = parsed_json[x]['response_code']
			if rcode == 0:
				print "\033[1;38m[!] DEMENTOR APT FOUND! \033[1;m"
				add_to_report(parsed_json[x]['resource'])
				apt_count += 1

			else:
				if parsed_json[x]['positives'] == 0:
					# ADD TO WHITELIST
					add_to_wlist(parsed_json[x]['sha1'])
					wlist_count += 1

				elif 0 < parsed_json[x]['positives'] <= 3:
					# COULD BE FALSE POSITIVE
					l_shaval = parsed_json[x]['sha1']
					cmds = 'grep -i %s filesystem.dobby' % l_shaval
					out = subprocess.Popen(cmds, shell=True, stdout=subprocess.PIPE)
					filepath = out.stdout.read()

					with open('reports/report.txt', 'a') as f:
						print "[?] FALSE POSITIVE?"
						f.write("\n[?] FALSE POSITIVE? - AV Detections: %s / %s" % (parsed_json[x]['positives'], parsed_json[x]['total']) )
						f.write("\n\tSHA1: %s" % parsed_json[x]['sha1'] + '\n')
						f.write("\tMD5: %s" % parsed_json[x]['md5'] + '\n')
						f.write(filepath + '\n')
						fp_count += 1

				else:
					with open('reports/report.txt', 'a') as f:
						print "\033[1;31m[+] BOGGART FOUND \033[1;m"
						f.write("\n[+] BOGGART FOUND \n")
						f.write("\tSHA1: %s" % parsed_json[x]['sha1'] + '\n')
						f.write("\tMD5: %s" % parsed_json[x]['md5'] + '\n')
						f.write("\tDetected: %s / %s" % (parsed_json[x]['positives'], parsed_json[x]['total']) + '\n')
						f.write('\n\tScan Report From: %s' % parsed_json[x]['scan_date'] + '\n')
						f.write("\t\t\tKaspersky:\t %s" % parsed_json[x]['scans']['Kaspersky']['result']+ '\n')
						f.write("\t\t\tTrendMicro:\t %s" % parsed_json[x]['scans']['TrendMicro']['result']+ '\n')
						f.write("\t\t\tSophos: \t %s" % parsed_json[x]['scans']['Sophos']['result']+ '\n')
						f.write("\t\t\tMcAfee: \t %s" % parsed_json[x]['scans']['McAfee']['result']+ '\n')
						f.write('\t\t\tMalwarebytes:\t %s' % parsed_json[x]['scans']['Malwarebytes']['result']+ '\n\n')

						f.write('\t\t\t[-] File: \n')
						cmd = 'grep -i %s filesystem.dobby' % parsed_json[x]['sha1']
						out = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
						fpath = out.stdout.read()
						f.write('\t\t\t%s \n\n' % fpath)
						malware_count += 1

			x -= 1

		print "-----------------------------------"
		print "[+] Malwares Found: %s" % malware_count
		print "[+] Suspected false-positives: %s" % fp_count
		print "[+] APT Samples Found: %s" % apt_count
		print "[+] Added to whitelist: %s" % wlist_count
		print "-----------------------------------"

		with open('reports/report.txt', 'a') as f:
			f.write("\n\n\t\t+-----------------------------------+"+ '\n')
			f.write("\t\t             ACCIO RESULTS"+ '\n')
			f.write("\t\t+-----------------------------------+"+ '\n')
			f.write("\t\t [+] Malwares Found: %s" % malware_count + '\n')
			f.write("\t\t [+] Suspected false-positives: %s" % fp_count + '\n')
			f.write("\t\t [+] APT Samples Found: %s" % apt_count + '\n')
			f.write("\t\t [+] Added to whitelist: %s" % wlist_count + '\n')
			f.write("\t\t+-----------------------------------+"+ '\n')

	except:
	#	print "[+] Unable to access the internet. Please check your network connection."
		tb = traceback.format_exc()
		print tb
