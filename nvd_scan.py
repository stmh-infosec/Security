#######################################################################################################################################################################
###nvd_scan.py                                                                                                                                                        #
###__author__ = 'Uday Bhaskar Seelamantula'																															                                                              #
###__Date__ =   '10/12/2015'                                                                                                                                          #
###Tool Description:                                                                                                                                                  #
###This tool can be used to scan for vulnerabilities that are present in 3rd party components that you use in your code/software.									                    #
###Notes: Vulnerabilities are divided with "**"*40 and each file is seperated by string "Processing file"                                                             #
###Functions Defined along with a short description: 																												                                                          #
###1) download(): This function downloads all the zip files from nvd website. The URLs are generated based on the existing time picked from the system.               #
###2) unzipper(): This function takes tester(to be unzipped files) as input(which is by default sent by download function; download function invokes the unzipper     #
###               function and starts decompressing itself. 																										                                                      #
###3) file_parser(): This function parses all the .xml file dumped into the nvd_cache folder and converts them into a human readable .txt file.This text file can     #
###					 further be used to make search operations. 																								                                                              #		
###4) update(): This function loads the  nvd updates from the nvdcve-Modified.xml file and converts them into a human readable .txt file. This text file can further  #
###             be used to make search operations. 																												                                                            #
###5) user_input() : This function takes the user input and performs the necessary actions like init and update.                                                      #
###6) help(): This function acts as a help module for the nvd_scan.py tool.                                                                                           #
###7) main(): This function acts is the main module that executes the nvd_scan.py script. 															                                    				  #
### Future work and Areas of improvements:																														                                                            	  #
### 1) Writing search functions to implement serach operations. 																					                                                  				  #
### 2) Code Parsers to serach through the code base to identify 3rd party libraries. 														                                        						  #
### 3) GUI and Web console for this tool. 																															                                                              #
### 4) Increase the size of vulnerability repository by fetching file from various sources.                                                                           #
#######################################################################################################################################################################
import sys
import urllib
import urllib2
import re
import csv
from urlparse import urlsplit
import os
from xml.dom.minidom import parse
import zipfile
import xml.dom.minidom
import glob
import commands
import hashlib
import time


###
#Function Name:download()
#Description: This function downloads all the zip files from nvd website. The URLs are generated based on the existing time picked from the system.
#These files are then dumped into the zipfiles folder. This function is a one time execution and should only be implemented during installation.
def download():
    print "Downloading in Progress"
    try:
        #file_open = open('download_url_patterns','r')
        for i in range(2002,int(time.strftime('%Y'))):
            line = "https://nvd.nist.gov/download/nvdcve-"+ str(i) +".xml.zip"
            t = urllib2.urlopen(line)
            meta = t.info()
            file_size = int(meta.getheaders("Content-Length")[0])
            print 'Downloading: '+ line + " Size: " + str(file_size)
            zip_file = line.split("/")
            data = t.read()
            with open('zipfiles'+'/'+ zip_file[-1], 'wb') as code:
                code.write(data)
                code.close()
                unzipper(zip_file[-1])
    except urllib2.HTTPError, error:
        print "HTTP_ERROR: ", str(error.message)
    except urllib2.URLError, error:
        print "URL_ERROR: ", str(error.message)

###
#Function Name:unzipper()
#Description: This function takes tester(to be unzipped files) as input(which is by default sent by download function; download function invokes the unzipper function)
#and starts decompressing it.
#Once the decompression is done, the xml files are dumped into nvd_cache folder.
def unzipper(tester):
    #print tester
    zip_rb = open('zipfiles'+'/'+ tester,'rb')
    print 'Unzipping: '+ tester
    z = zipfile.ZipFile(zip_rb)
    for x in z.infolist():
        print 'Compressed: ' , x.compress_size
        #print 'Uncompressed: ' , x.file_size
    for name in z.namelist():
        outfile = open('nvd_cache'+'/'+ name, 'wb')
        data = z.read(name)
        outfile.write(data)
        outfile.close()
    zip_rb.close()

###
#Function Name: file_parser()
#Description: This function parses all the .xml file dumped into the nvd_cache folder and converts them into a human readable .txt file.
#This text file can further be used to make search operations.
def file_parser():
    file = open("NVD.txt", "a+")
    filelist = []
    path = "/nvd_cache/"
    current = os.getcwd()
    os.chdir(current+path)
    for counter, files in enumerate(glob.glob("*.xml")):
        filelist.append(files)
    for filer in filelist:
        print "Processing file %s" % filer
        DOMTree = xml.dom.minidom.parse(filer)
        nvd = DOMTree.documentElement
        if nvd.hasAttribute("xmlns:scap-core"):
            print "xmlns:scap-core= %s" % nvd.getAttribute("xmlns:scap-core")
        vulns = nvd.getElementsByTagName("entry")
        for vuln in vulns:
            if vuln.hasAttribute("name"):
                file.write("Published: %s \n"% vuln.getAttribute("name"))
            if vuln.hasAttribute("severity"):
                file.write("Severity Level: %s \n"% vuln.getAttribute("severity"))
            descs = vuln.getElementsByTagName("desc")
            for desc in descs:
                description = desc.getElementsByTagName("descript")[0]
                defcon = description.childNodes[0].data
                encoded = defcon.encode('ascii', 'ignore').decode('ascii')
                file.write("Description: %s \n" % encoded)
            refs = vuln.getElementsByTagName("refs")
            for ref in refs:
                refers = ref.getElementsByTagName("ref")
                for refer in refers:
                    if refer.hasAttribute("url"):
                        file.write("URL: %s \n" % refer.getAttribute("url"))
            vulns_softs = vuln.getElementsByTagName("vuln_soft")
            for vuln_soft in vulns_softs:
                vuls = vuln_soft.getElementsByTagName("prod")
                for vul in vuls:
                    if vul.hasAttribute("name"):
                        file.write("**"*10+"\n")
                        file.write("Name: %s \n" % vul.getAttribute("name"))
                    if vul.hasAttribute("vendor"):
                        file.write("Vendor: %s \n" % vul.getAttribute("vendor"))
                    vers = vul.getElementsByTagName("vers")
                    for ver in vers:
                        vuln_versions = []
                        if ver.hasAttribute("num"):
                            file.write("Version: %s \n" % ver.getAttribute("num"))
                            vuln_versions.append("Version:"+ ver.getAttribute("num"))
                        if ver.hasAttribute("edition"):
                            file.write("Edition: %s \n" % ver.getAttribute("edition"))
                            vuln_versions.append("Edition:"+ ver.getAttribute("edition"))
                file.write("**"*40+"\n")
    file.close()
    os.chdir(current)

###
#Function Name: update()
#Description: This function loads the  nvd updates from the nvdcve-Modified.xml file and converts them into a human readable .txt file.
#This text file can further be used to make search operations.
def update():
    print "Updating Your NVD file"
    try:
        line = "https://nvd.nist.gov/download/nvdcve-Modified.xml.zip"
        t = urllib2.urlopen(line)
        meta = t.info()
        file_size = int(meta.getheaders("Content-Length")[0])
        print 'Downloading: '+ line + " Size: " + str(file_size)
        #zip_file = line.split("/")
        data = t.read()
        code = open('zipfiles'+os.sep+'nvdcve-Modified.xml.zip', 'wb')
        code.write(data)
        code.close()
        zip_rb = open('zipfiles'+os.sep+'/nvdcve-Modified.xml.zip','rb')
        print 'Unzipping: '+ 'nvdcve-Modified.xml.zip'
        z = zipfile.ZipFile(zip_rb)
        for x in z.infolist():
            print 'Compressed: ' , x.compress_size
            print 'Uncompressed: ' , x.file_size
        for name in z.namelist():
            outfile = open('nvd_cache'+'/'+ name, 'wb')
            read_data = z.read(name)
            outfile.write(read_data)
            outfile.close()
        zip_rb.close()
        os.remove('zipfiles/nvdcve-Modified.xml.zip')
        if os.path.exists('NVD_Updates.txt'):
            os.remove('NVD_Updates.txt')
        file = open("NVD_Updates.txt", "a+")
        path = "/nvd_cache/"
        current = os.getcwd()
        os.chdir(current+path)
        print "Processing file nvdcve-Modified.xml"
        DOMTree = xml.dom.minidom.parse("nvdcve-Modified.xml")
        nvd = DOMTree.documentElement
        if nvd.hasAttribute("xmlns:scap-core"):
            print "xmlns:scap-core= %s" % nvd.getAttribute("xmlns:scap-core")
        vulns = nvd.getElementsByTagName("entry")
        for vuln in vulns:
            if vuln.hasAttribute("name"):
                file.write("Published: %s \n"% vuln.getAttribute("name"))
            if vuln.hasAttribute("severity"):
                file.write("Severity Level: %s \n"% vuln.getAttribute("severity"))
            descs = vuln.getElementsByTagName("desc")
            for desc in descs:
                description = desc.getElementsByTagName("descript")[0]
                defcon = description.childNodes[0].data
                encoded = defcon.encode('ascii', 'ignore').decode('ascii')
                file.write("Description: %s \n" % encoded)
            refs = vuln.getElementsByTagName("refs")
            for ref in refs:
                refers = ref.getElementsByTagName("ref")
                for refer in refers:
                    if refer.hasAttribute("url"):
                        file.write("URL: %s \n" % refer.getAttribute("url"))
            vulns_softs = vuln.getElementsByTagName("vuln_soft")
            for vuln_soft in vulns_softs:
                vuls = vuln_soft.getElementsByTagName("prod")
                for vul in vuls:
                    if vul.hasAttribute("name"):
                        file.write("**"*10+"\n")
                        file.write("Name: %s \n" % vul.getAttribute("name"))
                    if vul.hasAttribute("vendor"):
                        file.write("Vendor: %s \n" % vul.getAttribute("vendor"))
                    vers = vul.getElementsByTagName("vers")
                    for ver in vers:
                        vuln_versions = []
                        if ver.hasAttribute("num"):
                            file.write("Version: %s \n" % ver.getAttribute("num"))
                            vuln_versions.append("Version:"+ ver.getAttribute("num"))
                        if ver.hasAttribute("edition"):
                            file.write("Edition: %s \n" % ver.getAttribute("edition"))
                            vuln_versions.append("Edition:"+ ver.getAttribute("edition"))
                file.write("**"*40+"\n")
        file.close()
        os.chdir(current)
        os.remove('nvd_cache' + os.sep + 'nvdcve-Modified.xml')
    except urllib2.HTTPError, error:
        print "HTTP_ERROR: ", str(error.message)
    except urllib2.URLError, error:
        print "URL_ERROR: ", str(error.message)

###
#Function Name: user_input()
#Description: This function takes the user input and performs the necessary actions like init and update.
def user_input():
    if len(sys.argv) == 2:
        decision = str(sys.argv[1])
        if decision == '--help':
            help()
        elif decision == 'update':
            if not os.path.exists('zipfiles'):
                os.mkdir('zipfiles')
            if not os.path.exists('nvd_cache'):
                os.mkdir('nvd_cache')
            update()
            print "Your NVD is now updated..!"
            exit()
        elif decision == 'init':
            if not os.path.exists('zipfiles'):
                os.mkdir('zipfiles')
            if not os.path.exists('nvd_cache'):
                os.mkdir('nvd_cache')
            download()
            file_parser()
            print "You are all set to perform scans..!"
            exit()
        elif decision == 'exit':
                exit()
        else:
            print "Please enter a valid String"
            print "\n\tuse python nvd_scan.py --help for help"
            exit()
    else:
        print "Please enter a valid String"
        print "\n\tuse python nvd_scan.py --help for help"
        exit()

###
#Function Name: help()
#Description: This function acts as a help module for the nvd_scan.py tool.
def help():
    print "Usage:"
    print "\t nvd_scan.py <command>"
    print "\t Example:"
    print "\t nvd_scan.py init"
    print "Useful Commands: "
    print "\t init - Init initializes nvd_scan"
    print "\t update  - Downloads new copies of NVD feeds, recommend running daily"
    print "\t exit - exits the oss_scan tool"
    print "\t Eg: python oss_scan.py init"
    exit()
###
#Function Name: main()
#Description: This function acts is the main module that executes the nvd_scan.py script.
def main():
    try:
        test = user_input()
    except TypeError:
        print "Seems like you have not typed the command correctly...!"
        print "If you are not sure of how to use the tool, please used the --help command to see the options available"


if __name__ == '__main__':
    main()
