# asterisk-pri-hexdump2pcap

Converts an Asterisk PRI ISDN hexdump textfile into a Wireshark-compatible pcap

Usage:
```bash
asterisk> pri set debug hex span 1
asterisk> pri set debug file dchannel.txt
linux$ ./hexdump2pcap.py dchannel.txt dchannel.pcap
```

![Wireshark screenshot](https://screenshot.tbspace.de/ebladtkjiqr.png)
