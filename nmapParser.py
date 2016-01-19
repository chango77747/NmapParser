#!/usr/bin/python
# Evan Pena
# evan.pena@mandiant.com
# Mandiant 2012
#This script will recursively look through nmap files and subfolders for hostname/IPs that are online, offline, or any.
#from __future__ import print_function
#above import is  the pythong thing for importing the print function works on 2.6 and up

import os, re, sys, threading, datetime
from optparse import OptionParser, OptionGroup
from xml.dom.minidom import parse, parseString
from array import *

class NmapParser(threading.Thread):

	def __init__(self):
		threading.Thread.__init__(self)
		self.dir = []	
		self.hostname = []		
		self.file = []
		self.root = []	
		self.request = []
		self.lines = []
		self.hosts = ""
		self.index = 0
		self.total=[]
		self.online=[]
		self.offline= 0
		self.dirList = ""
		#self.tNum = 0
		#print "Thread %s" % (self.tNum)
	
	def enumer(self, lines, request, hosts, verbose):
		try:
			self.lines = lines
			self.request = request
			self.hosts = hosts
			
			if (self.request == 'online'):
				for line in lines:					
					if ("report" in line and 'down' not in line):
						if self.hosts == True:						
							self.hostname = re.findall('([-a-zA-Z0-9\.]+\.[-a-zA-Z0-9\.]+\.[-a-zA-Z0-9\.]+)', line)
							if (self.hostname and len(self.hostname) > 1):								
								self.hostname = str(self.hostname)
								self.hostname = self.hostname.replace("[", "")
								self.hostname = self.hostname.replace("]", "")
								self.hostname = self.hostname.replace("'", "")					
								print self.hostname
								self.index +=1
						else: 						
							self.hostname = re.findall('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', line)
							if (self.hostname):									
								if (len(self.hostname) > 1):								
									self.hostname = str(self.hostname)
									self.hostname = self.hostname.replace("[", "")
									self.hostname = self.hostname.replace("]", "")
									self.hostname = self.hostname.replace("'", "")
									self.hostname = self.hostname.split(",")
									print self.hostname[0]
								else:
									self.hostname = str(self.hostname)
									self.hostname = self.hostname.replace("[", "")
									self.hostname = self.hostname.replace("]", "")
									self.hostname = self.hostname.replace("'", "")					
									print self.hostname
					else: pass
					if ("done" in line):
						total = re.findall("(\d+)\s+IP address",line)
						online = re.findall("(\d+)\s+hosts up",line)
						total = int(total[0])
						online = int(online[0])
						self.total.append(total)
						self.online.append(online)
					else: pass
				if (verbose == 2 and self.hosts == False):
					print "\nFound " + str(sum(self.online)) + " online hosts out of " + str(sum(self.total)) + " hosts."
				elif (verbose == 2 and self.hosts == True):
					print "\nTotal hostnames found online: " + str(self.index)
				else: pass
					
			elif (self.request == 'offline'):
				for line in lines:					
					if ("report" in line and 'down' in line):
						if self.hosts == True:						
							self.hostname = re.findall('([-a-zA-Z0-9\.]+\.[-a-zA-Z0-9\.]+\.[-a-zA-Z0-9\.]+)', line)
							if (self.hostname and len(self.hostname) > 1):					
								self.hostname = str(self.hostname)
								self.hostname = self.hostname.replace("[", "")
								self.hostname = self.hostname.replace("]", "")
								self.hostname = self.hostname.replace("'", "")					
								print self.hostname
								self.index +=1
						else: 						
							self.hostname = re.findall('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', line)
							if (self.hostname):
								if (len(self.hostname) > 1):								
									self.hostname = str(self.hostname)
									self.hostname = self.hostname.replace("[", "")
									self.hostname = self.hostname.replace("]", "")
									self.hostname = self.hostname.replace("'", "")
									self.hostname = self.hostname.split(",")
									print self.hostname[0]
								else:
									self.hostname = str(self.hostname)
									self.hostname = self.hostname.replace("[", "")
									self.hostname = self.hostname.replace("]", "")
									self.hostname = self.hostname.replace("'", "")					
									print self.hostname
					else: pass
					if ("done" in line):
						total = re.findall("(\d+)\s+IP address",line)
						online = re.findall("(\d+)\s+hosts up",line)
						total = int(total[0])
						online = int(online[0])
						self.total.append(total)
						self.online.append(online)
					else: pass
					
				if (verbose == 2 and self.hosts == False):
					self.offline = sum(self.total) - sum(self.online)
					print "\nFound " + str(self.offline) + " offline hosts out of " + str(sum(self.total)) + " hosts."
				elif (verbose == 2 and self.hosts == True):
					print "\nTotal hostnames found offline: " + str(self.index)
				else: pass
			else:
				for line in lines:					
					if ("report" in line):
						if self.hosts == True:
							self.hostname = re.findall('([-a-zA-Z0-9\.]+\.[-a-zA-Z0-9\.]+\.[-a-zA-Z0-9\.]+)', line)
							if (self.hostname and len(self.hostname) > 1):					
								self.hostname = str(self.hostname)
								self.hostname = self.hostname.replace("[", "")
								self.hostname = self.hostname.replace("]", "")
								self.hostname = self.hostname.replace("'", "")					
								print self.hostname
								self.index +=1
						else: 						
							self.hostname = re.findall('(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})', line)
							if (self.hostname):
								if (len(self.hostname) > 1):								
									self.hostname = str(self.hostname)
									self.hostname = self.hostname.replace("[", "")
									self.hostname = self.hostname.replace("]", "")
									self.hostname = self.hostname.replace("'", "")
									self.hostname = self.hostname.split(",")
									print self.hostname[0]
								else:
									self.hostname = str(self.hostname)
									self.hostname = self.hostname.replace("[", "")
									self.hostname = self.hostname.replace("]", "")
									self.hostname = self.hostname.replace("'", "")					
									print self.hostname
					if ("done" in line):
						total = re.findall("(\d+)\s+IP address",line)
						online = re.findall("(\d+)\s+hosts up",line)
						total = int(total[0])
						online = int(online[0])
						self.total.append(total)
						self.online.append(online)
					else: pass				
				
				if (verbose == 2 and self.hosts == False):					
					#print "\nFound " + str(self.total) + " total hosts out of " + str(sum(self.total)) + " hosts."
					self.offline = sum(self.total) - sum(self.online)
					print "\nNmap scanned a total of " + str(sum(self.total)) + " hosts."
					print "Nmap found " + str(sum(self.online)) + " hosts online."
					print "Nmap found " + str(self.offline) + " hosts offline."
				elif (verbose == 2 and self.hosts == True):
					print "\nTotal hostnames found: " + str(self.index)
					
				else: pass
		except Exception, e:
			print e
		
	def recursiveEnum(self, dir, hosts, request, verbose):
		try:
			self.dir = dir
			self.request = request
			self.hosts = hosts
			
			for self.root, self.dirs, self.file in os.walk(self.dir):
				for file in self.file:	
					if (file and file.endswith('.nmap')):			
						path = os.path.join(self.root, file)						
						lines = open(path, 'r').readlines()					
						self.enumer(lines, self.request, self.hosts, verbose)
			
			if (verbose == 1 and self.request == 'online' and self.hosts == False):
				print "\nFound " + str(sum(self.online)) + " online hosts out of " + str(sum(self.total)) + " hosts."
			elif (verbose == 1 and self.request == 'offline' and self.hosts == False):
				self.offline = sum(self.total) - sum(self.online)
				print "\nFound " + str(self.offline) + " offline hosts out of " + str(sum(self.total)) + " hosts."
			elif (verbose == 1 and self.request == 'offline' and self.hosts == True):
					print "\nTotal hostnames found offline: " + str(self.index)
			elif (verbose == 1 and self.request == 'online' and self.hosts == True):
					print "\nTotal hostnames found online: " + str(self.index)
			elif(verbose ==1 and self.hosts == True):
				print "\nTotal hostnames found: " + str(self.index)
			elif (verbose == 1 and self.hosts == True):
					print "\nTotal hostnames found: " + str(self.index)	
			elif(verbose ==1): 
				self.offline = sum(self.total) - sum(self.online)
				print "\nNmap scanned a total of " + str(sum(self.total)) + " hosts."
				print "Nmap found " + str(sum(self.online)) + " hosts online."
				print "Nmap found " + str(self.offline) + " hosts offline."
			else:pass
		except Exception, e:
			print e
	
	def enumDir(self, dir, dirList, hosts, request, verbose):
		try:
			self.root = dir
			self.hosts = hosts
			self.request = request
			self.dirList = dirList
			for self.file in self.dirList:
				if (self.file.endswith('.nmap')):
					path = os.path.join(self.root, self.file)				
					lines = open(path, 'r').readlines()
					self.enumer(lines, self.request, self.hosts, verbose)
			
			if (verbose == 1 and self.request == 'online' and self.hosts == False):
				print "\nFound " + str(sum(self.online)) + " online hosts out of " + str(sum(self.total)) + " hosts."
			elif (verbose == 1 and self.request == 'offline' and self.hosts == False):
				self.offline = sum(self.total) - sum(self.online)
				print "\nFound " + str(self.offline) + " offline hosts out of " + str(sum(self.total)) + " hosts."
			elif (verbose == 1 and self.request == 'offline' and self.hosts == True):
					print "\nTotal hostnames found offline: " + str(self.index)
			elif (verbose == 1 and self.request == 'online' and self.hosts == True):
					print "\nTotal hostnames found online: " + str(self.index)
			elif (verbose == 1 and self.hosts == True):
					print "\nTotal hostnames found: " + str(self.index)		
			elif(verbose ==1): 
				self.offline = sum(self.total) - sum(self.online)
				print "\nNmap scanned a total of " + str(sum(self.total)) + " hosts."
				print "Nmap found " + str(sum(self.online)) + " hosts online."
				print "Nmap found " + str(self.offline) + " hosts offline."
			else:pass
			
		except Exception, e:
			print e
			
class EverythingParse(threading.Thread):
	try:
		def __init__(self,recursive, dir = '', output='output.csv', dom = ''):
			threading.Thread.__init__(self)
			#self.dom = dom			self.nmapvars = {}			self.hostname = ''			self.os = ''			self.difficulty = ''			self.args = ''
			self.ipaddr = ''			self.date = ''			self.port = []			self._name = []			self.protocol = []						self.product = []			self.version = []			self.extrainfo = []			self.portstate = []			self.goodXML = []
			self.dirOutput = output
			self.recursive = recursive
			self.dir = dir
						
			# start output file
			self.output = open(self.dirOutput, 'a')
			self.output.write('\n<----started at: ')

			#get current time and put in self.output file
			self.now = datetime.datetime.now()
			print ""
			self.output.write(self.now.strftime("%Y-%m-%d %H:%M"))
			self.output.write(' ----->\n')
			self.output.write(',,,,,,,,,\n')
			self.output.write('IP Address,Host Name,All Ports Filtered,Open Ports,')
			self.output.write('State (O/C),Service,Version,Device Type,Running,OS Details\n')
			
			#Recursive options
			if (self.recursive):
				for root, dirs, files in os.walk(self.dir):
					for file in files:	
						if (file and file.endswith('.xml')):	
							path = os.path.join(root, file)
							self.dom = parse(path)
							theFilename = path.split('\\')
							print "Parsing: " + theFilename[len(theFilename)-1]
							self.breakDown()
			elif(dom==''):				
				dirList = os.listdir(self.dir)	
				for files in dirList:
					if (files.endswith('.xml')):					
						path = os.path.join(dir, files)					
						self.dom = parse(path)
						print "Parsing: " + files
						self.breakDown()
			else:
				self.dom = parse(dom)
				print dom
				theFilename = options.xmlfile.split('\\')
				print "Parsing: " + theFilename[len(theFilename)-1]
				self.breakDown()
			
			self.scaninfo = self.dom.getElementsByTagName('nmaprun')[0]
			self.date = self.scaninfo.getAttribute("startstr")
			self.args = self.scaninfo.getAttribute('args')
			
			self.dom.unlink()
			self.output.close()			
		
		#define translateXml
		def translateXml(self, node):
			try:
				if node.nodeName == 'hostname':

					self.hostname = node.getAttribute('name')
					self.output.write(node.getAttribute('name'))
					self.output.write(',')

				elif node.nodeName == 'address':

					if 'ip' in node.getAttribute('addrtype'):

						self.output.write('\n')
						#self.output.write(',')
						self.ipaddr = node.getAttribute('addr')
						self.output.write(node.getAttribute('addr'))
						self.output.write(',')

				elif node.nodeName == "port":

					#protocol.append(node.getAttribute("protocol"))
					#self.output.write(node.getAttribute("protocol"))
					#self.output.write(',')

					self.output.write('\n')
					self.output.write(self.ipaddr)
					self.output.write(',')
					self.output.write(',')
					self.output.write(',')
					self.port.append(node.getAttribute("portid"))
					#self.output.write(addr)
					self.output.write(node.getAttribute("portid"))
					self.output.write(',')

				elif node.nodeName == "state":

					self.portstate.append(node.getAttribute('state'))
					self.output.write(node.getAttribute('state'))
					self.output.write(',')

				elif node.nodeName == "service":

					self._name.append(node.getAttribute("name"))
					self.output.write(node.getAttribute('name'))
					self.output.write(',')
					self.product.append(node.getAttribute("product"))
					self.output.write(node.getAttribute('product'))
					self.output.write(',')
					self.version.append(node.getAttribute("version"))
					self.output.write(node.getAttribute('version'))
					self.output.write(',')
					self.extrainfo.append(node.getAttribute("extrainfo"))
					self.output.write(node.getAttribute('extrainfo'))
					self.output.write(',')

				elif node.nodeName == 'osmatch':

					self.os = node.getAttribute('name')
					self.output.write(node.getAttribute('name'))
					self.output.write(',')

				elif node.nodeName == 'tcpsequence':

					self.difficulty = node.getAttribute('difficulty')
			
			except Exception, e:
				print e
		
		def breakDown(self):			
			try:
				for node in self.dom.getElementsByTagName('host'):

					#second level within host tag
					for subnode in node.childNodes: #go through each subnode of

						if subnode.attributes is not None: #if the subnode has attributes parse them

							self.translateXml(subnode) #send the attribute to translateXml
							if len(subnode.childNodes) > 0: #if there are childnodes then dig deeper

								#third level
								for subsubnode in subnode.childNodes: #loop through childnodes

									if subsubnode.attributes is not None: #if the susubnode has attributes parse them

										self.translateXml(subsubnode) #send the attribute to translateXml

										if len(subsubnode.childNodes) > 0:

											#fourth level
											for subsubsubnode in subsubnode.childNodes:

												if subsubsubnode.attributes is not None:

													self.translateXml(subsubsubnode) #translate the xml
							
			except Exception, e:
				print e
	
	except Exception, e:
			print e

if __name__ == '__main__':
	try:
		fileOut = 'output.csv'			
	
		usage = "usage: " + os.path.basename(sys.argv[0]) + " [options] args1"
		parser = OptionParser(usage=usage)
		
		parser.add_option("-d", "--directory", dest="directory",
						  help="Directory to parse through")
		parser.add_option("-r", "--recursive", action="store_true", dest="recursive",
						  help="This will include all subfolders of the given directory", default=False)
		parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
						  help="Enable additional details in the output.", default=False)
		
		everything = OptionGroup(
			parser, 'XML Options',
			'This is a seperate group to only parse xml files and output all results to a csv file.')
		everything.add_option("-e", "--everything", action="store_true", dest="everything",
						  help="The option to parse everything in from the nmap xml file", default=False)
		everything.add_option("-x", "--xml", dest="xmlfile",
						  help="XML file to parse")
		everything.add_option("-o", "--output", dest="output",
						  help="Destination you want the output to be.")
		parser.add_option_group(everything)				
		
		nmap = OptionGroup(
			parser, 'Nmap file options',
			'These are the options used only for .nmap files.')
		nmap.add_option("-n", "--hostnames", action="store_true", dest="hostnames",
						  help="Search target path for hostname, ip", default=False)
		nmap.add_option("--online", action="store_true", dest="online",
						  help="This will only look for hosts that were online", default=False)
		nmap.add_option("--offline", action="store_true", dest="offline",
						  help="This will only look for hosts that were offline", default=False)
		nmap.add_option("-a", "--all", action="store_true", dest="all",
						  help="This will look for all hosts in the target path. This is default.", default=False)
		nmap.add_option("-f", "--filename",  dest="filename",
						  help="Filename.nmap to parse through")
		parser.add_option_group(nmap)
		
		parser.add_help_option = True
		threads = []		
		(options, args) = parser.parse_args()
		tNum = 0
		dir = options.directory
		
		#Checking to see if the user put in arguments that cannot be combined.
		if (options.online and options.offline):
			parser.error("options -online and -offline are mutually exclusive")
		elif (options.online and options.all):
			parser.error("options -online and -all are mutually exclusive")
		elif (options.offline and options.all):
			parser.error("options -offline and -all are mutually exclusive")
		elif (dir == None and options.recursive):
			parser.error("You need a directory if you are going to recursively search through one.")
		elif ((options.directory and options.filename) or (options.directory and options.xmlfile)):
			parser.error("Inputs filename/xml and directory are mutually exclusive.")		
		#elif((options.xmlfile == None and options.everything == False) or (options.directory == None and options.everything == False)):
		#	parser.error("You must have some kind of input.")
		elif (options.xmlfile and options.filename):
			parser.error("Inputs filename and xml are mutually exclusive.")
				
		if (options.online):
			request = 'online'
		elif (options.offline):
			request = 'offline'
		else: request = 'all'
		
		if (options.verbose):
			verbose = 1
		else: verbose = 0
		
		#Checks the output option
		if (options.output != None):
			fileOut = options.output
			if fileOut.endswith('.csv'):
				pass
			elif not fileOut.endswith(os.path.sep):
				fileOut += os.path.sep
				fileOut += 'output.csv'
			else:
				fileOut += 'output.csv'
			
		
		#parses a single xml file
		if (options.xmlfile != None and options.everything != False):
			eparse = EverythingParse(options.recursive, fileOut, fileOut, options.xmlfile)			
		
		#Parses all xml files within dir Recusively to include sub-folders
		elif (dir != None and options.everything != False and options.recursive):
			if not dir.endswith(os.path.sep):
				dir += os.path.sep
			eparse = EverythingParse(options.recursive, dir, fileOut)
						
		#Parses all xml files within dir
		elif (dir != None and options.everything != False):
			eparse = EverythingParse(options.recursive, dir, fileOut)
			
		#Recusively enumerate a directory
		elif (dir != None and options.recursive):			
			if not dir.endswith(os.path.sep):
				dir += os.path.sep
				print dir
			parser = NmapParser()
			parser.recursiveEnum(dir, options.hostnames, request, verbose)
							
		
		#Do just enumerate that particular directory.
		elif (dir!=None and options.everything == False):								
			if not dir.endswith(os.path.sep):
				dir += os.path.sep
			dirList = os.listdir(dir)	
			parser = NmapParser()
			parser.enumDir(dir, dirList, options.hostnames, request, verbose)
		
		#Enumerates the lines within the file specified
		elif (options.filename!=None):
			if (options.verbose):
				verbose = 2
			else:pass
			parser = NmapParser()
			lines = open(options.filename, 'r').readlines()			
			parser.enumer(lines, request, options.hostnames, verbose)
				
			
		else: print usage
	except Exception, e:
		print e
	