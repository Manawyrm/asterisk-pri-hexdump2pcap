#!/usr/bin/env python3
# 
# asterisk-pri-hexdump2pcap
# Converts an Asterisk PRI ISDN hexdump textfile into a Wireshark-compatible pcap
# https://github.com/Manawyrm 
#
# Usage:
# asterisk> pri set debug hex span 1
# asterisk> pri set debug file dchannel.txt
# linux$ ./hexdump2pcap.py dchannel.txt dchannel.pcap
#
# (requires Wireshark / text2pcap utility to be installed)
#
import argparse
import pathlib
import subprocess

parser = argparse.ArgumentParser(
	description='Converts an Asterisk "pri set debug file" hexdump into a pcap'
	)
parser.add_argument('inputfile', metavar='INPUTFILE', type=pathlib.Path,
			help='filename of hexdump from "pri set debug file"')
parser.add_argument('outputfile', metavar='OUTPUTFILE', type=pathlib.Path,
			help='filename of .pcap output')

args = parser.parse_args()

inputfile_handle = open(args.inputfile, 'r')

# LINKTYPE_LINUX_LAPD 177 - https://www.tcpdump.org/linktypes.html
command = ['text2pcap', '-l', '177', '-', args.outputfile]

p = subprocess.Popen(command, stdin=subprocess.PIPE)

while True:
	line = inputfile_handle.readline()
	if not line:
		break

	line = line.strip()
	line = line.replace("[", "")
	line = line.replace("]", "")

	if line == "":
		continue

	# https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_LAPD.html
	if line[0] == "<":
		# outbound packet
		# packet type field - 4, if the packet was sent by us
		header = "000000 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 30 "

	if line[0] == ">":
		# inbound packet
		# packet type field - 0, if the packet was sent to us by somebody else
		header = "000000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 30 "

	# Let's strip the inbound/outbound markers and spaces
	line = line.replace(">", "")
	line = line.replace("<", "")
	line = line.strip()

	p.stdin.write((header + line + "\n").encode("utf-8"))
	p.stdin.flush()

p.stdin.close()
p.wait()

inputfile_handle.close()