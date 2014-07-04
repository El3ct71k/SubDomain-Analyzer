SubDomain Analyzer
==================

The Subdomain Analyzer is tool written on Python language to try to get full details about domains.
The Subdomain Analyzer gets a data from domain by following steps:
1. Trying to Analyzer the `zone tranfer` file
2. Gathers all informations from DNS Records
3. Analyzing the DNS Records (Analyzing all the IP addresses from DNS records and test all the range from IP address(For example: 127.0.0.1/24) and gets all the data that containing the domain being analyzed)
4. tests subdomains by dictionary attack

The Subdomain Analyzer can keep new addresses which found on DNS records or  IP Analyzer
The Subdomain Analyzer can brings a very qualitative information about the domain being analyzed,
additionally, he shows a designed report with all the data

#####Examples:
Analyze the example.com domain:
subdomain-analyzer.py example.com
analyze the example.com domain, save the records on `log.txt` file with 100 threads and use by another dictionary file:
subdomain-analyzer.py example.com --output log.txt --threads 100 --sub-domain-list another-file.txt
analyze the example.com domain, save the records on `log.txt` and append new sub-domains to sub-domainslist:
subdomain-analyzer.py example.com --output log.txt --sub-domain-list

Requirements:
===============
###Linux Installation:
1. sudo apt-get install python-dev python-pip
2. sudo pip install -r requirements.txt
3. easy_install prettytable

###MacOSx Installation:
1. Install Xcode Command Line Tools (AppStore)
2. sudo easy_install pip, prettytable
3. sudo pip install -r requirements.txt

###Windows Installation:
1. Install [dnspython](http://www.dnspython.org/)
2. Install [gevent](http://www.lfd.uci.edu/~gohlke/pythonlibs/#gevent)
3. Install [prettytable](https://pypi.python.org/pypi/PrettyTable)
4. Open Command Prompt(cmd) as Administrator -> Goto python folder -> Scripts (cd c:\Python27\Scripts)
5. pip install -r (Full Path To requirements.txt)
6. easy_install prettytable
