#1. Name
SapCap - SAP GUI protocl sniffer / decompressor
#2. Author
Ian de Villiers < ian(at)sensepost(dot)com >
#3. License, version & release date
License : GPL  
Version : V0.1  
Release Date : 2011/09/02

#4. Description
SApCap is a SAP packet sniffer and decompression tool for analysing SAP GUI (DIAG) traffic.
Using a 3rd-party JNI interface for pCap, it is also able to load previously captured tcpdump files.
#5. Usage
> java -jar SApCap.jar
#6. Requirements
Java runtime environment.  
Jpcap (http://netresearch.ics.uci.edu/kfujii/Jpcap/doc/index.html)  
Custom JNI Library.

The custom JNI library is included in the download.

Binary builds of the JNI library are only available for the following platforms:  
Mac OS/X  
Windows (32-bit)  
Linux (32-bit)

Please note: The JNI libraries required for the platform must be kept in ./lib.
#7. Additional Resources 
System Application Proxy Pwnage - www.sensepost.com/cms/resources/labs/tools/poc/sapcap/44con\_2011\_release.pdf  
Blog post - http://www.sensepost.com/blog/6021.html
