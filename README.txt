Developer: Evan Pena

nmapParser.py is a tool developed for consultants doing nmap scans against a large range of hosts. I found it easy to identify hosts that are:
•	Online
•	Offline
•	Hostnames only
•	All hosts you scanned

What is unique about this tool is that it allows the user to parse a file, directory of files, or recursively parse a directory.

Examples:
This will parse all .nmap files in a directory for IP addresses that were online:
nmapParser.py  -d [directory] -–online

This will parse all .nmap files recursively (including sub-folders) in a directory for IPs that are offline:
nmapParser.py  -r -d [directory] –-offline

This will parse 1 .nmap file for IP addresses that have a hostname:
nmapParser.py  -f [filename.nmap] –hostnames

Or you can recursively parse a directory for .nmap files for hostnames that were offline:
nmapParser.py  -r -d [directory] –-offline –hostnames

The XML Options area is an area that will parse the nmap xml output and output the results into a csv file.
Examples:

This will parse an 1 xml file and output the results to orange.csv:
nmapParser.py -e -x [filename.xml] – o [path/orange.csv]

This will parse a directory for nmap xml files and output it to folder.csv:
nmapParser.py -e -d [directory]  – o [path/folder.csv]

Sometimes you have a TON of results for XXX client so you want to just parse the root directory of xxx client for all the results. This is where the recursive option comes in play again:
nmapParser.py -e –r -d [directory]  – o [path/xxx.csv]
