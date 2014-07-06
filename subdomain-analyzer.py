#!/usr/bin/env python
__author__ = ['Nimrod Levy', 'Tomer Zait']
__license__ = 'GPL v3'
__version__ = '0.1'
__email__ = ['El3ct71k@gmail.com', 'TzAnAnY@Gmail.com']

from gevent.monkey import patch_all
patch_all()
from gevent.pool import Pool
import sys
import logging
import re
import socket
import dns
from os import path
from argparse import ArgumentParser
from collections import defaultdict
from prettytable import PrettyTable
from dns import resolver, query, zone
from dns.exception import FormError, Timeout


# Global Variables
OCT_LIST = set()
REPORT_DETAILS = defaultdict(set)
POTENTIAL_SUBDOMAINS = set()


class SubDomainAnalyzer(object):
    def __init__(self, output, threads, append_sub_domains, sub_domain_list, socket_timeout=5):
        # Root Domain (From Main)
        self.root_domain = None

        if not path.exists(sub_domain_list): # Checks if the `subdomain` file exists
            raise Exception('Sub-domains list not found.')
        # Settings
        self.sub_domain_file_name = sub_domain_list
        self.sub_domain_list = set(self.__get_sub_domains_list())
        self.append_sub_domains = append_sub_domains
        self.logger = self.create_logger(output)
        self.__ip_pool = Pool(size=threads)
        self.__domain_pool = Pool(size=threads)

        # Set socket timeout
        socket.setdefaulttimeout(socket_timeout)

    @staticmethod
    def __oct_builder(ip):
        '''
            This function is responsible to split the dots, delete the third dot from the number and finally, will join to the dots rest.
            For Example:
            __oct_builder("127.0.0.1")
            return: 127.0.0
        '''
        return '.'.join(ip.split('.')[0:-1])

    @staticmethod
    def __is_public(ip):
        '''
            This function checks if the ip is public or private
            For example:
                __is_public("192.168.0.1")
                return: False
        '''
        if re.match(r'^(?:10)(?:\.\d+){3}|(?:172\.(?:[1]:?[0-9]|[2]:?[0-9]|[3]:?[0-1]))(?:\.\d+){2}|(?:192.168)(?:\.\d+){2}|(?:127)(?:\.\d+){3}$', ip):
            return False
        return True

    @staticmethod
    def __resolve_par(par):
        '''
            This function checks if the `par` contains string or list.
            If it contains a list, he join the strings from the list and will return him,
            if not, he will returns the string
        '''
        if isinstance(par, list):
            return "".join(par)
        return par

    @staticmethod
    def __get_ips(ip, ip_range=255):
        '''
            This function is responsible to get a partial IP address and generate 255 complete IP addresses
            For example:
                __get_ips('127.0.0.1', ip_range=3)
                return: ['127.0.0.1', '127.0.0.2', '127.0.0.3']
        '''
        oct_ip = SubDomainAnalyzer.__oct_builder(ip)
        for i in xrange(1, ip_range + 1):
            yield "{oct}.{end}".format(oct=oct_ip, end=i)

    @staticmethod
    def create_logger(outfile=None):
        '''
            This function is responsible to create records and show the responses with designed logger,
            if `outfile` parameter not set on None, he create a new file by name from `output` string and save the records on him.
        '''
        logger = logging.getLogger('SubSubDomainAnalyzer') # Create logger
        logger.setLevel(logging.INFO)                   # Set logger level

        # Create console handler
        formatter = logging.Formatter(
            fmt='[%(asctime)s] %(message)s',
            datefmt='%d-%m-%Y %H:%M'
        )
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        if outfile:     # If out file not None, he creates the file handler
            fh = logging.FileHandler(outfile)
            fh.setFormatter(logging.Formatter('%(message)s'))
            logger.addHandler(fh)

        return logger

    def __get_sub_domains_list(self):
        '''
            This function is responsible open the `subdomain` file, create list of subdomains and return the list
        '''
        with open(self.sub_domain_file_name) as sub_domain_file:
            for line in sub_domain_file:
                sub_domain = line.rstrip()
                if sub_domain: # Checks if the subdomain is not None
                    yield sub_domain

    def __add_new_sub_domains(self):
        '''
            This function is responsible to get a two lists:
                1. List of potential of subdomains (Subdomains from dns data or IP Analayzer that might not exist on `subdomains` file)
                2. List of subdomains file
            and checks if have a subdomain on potential subdomains list which dont exist on `subdomains` file.
            If have a new subdomain on potential list which dont exists on `subdomains` file, he append him to the `subdomains` file
        '''
        with open(self.sub_domain_file_name, 'a') as sub_domain_file:
            sub_domain_file.write("\n")
            sub_domain_file.flush()
            for new_sub_domain in POTENTIAL_SUBDOMAINS:
                if new_sub_domain not in self.sub_domain_list:
                    self.logger.info("adding '%s' to sub domains list" % new_sub_domain)
                    sub_domain_file.write("%s\n" % new_sub_domain)
                    sub_domain_file.flush()

    @staticmethod
    def zone_transfer(logger, url):
        '''
            This function is responsible to try to get the `zone transfer` file.
            If he success, he shows the `zone transfer` file and he will finish.

            How this function works?
            he get all the DNS Records and try to get the `zone transfer` file by all the records.
            If he failed, he will continue to try to get the `zone transfer file` by the next DNS record.
            If all the records will fail, we cant to get a `zone transfer` file.
            The function will returns false value.
        '''
        try:
            logger.info("[DNS] Trying zone transfer first..")
            answers = resolver.query(url, 'NS')
            for ns in (ns.to_text().rstrip('.') for ns in answers):
                try:
                    z = zone.from_xfr(
                        query.xfr(ns, url)
                    )
                    zone_record = "\n".join(z[z_node].to_text(z_node) for z_node in z.nodes.keys())
                    logger.info("[DNS] Zone file:!\n%s" % zone_record)
                    return True
                except socket.error:
                    pass
        except (FormError, dns.resolver.NoAnswer, dns.exception.Timeout, EOFError):
            pass
        except Exception as e:
            logger.error('[DNS][Error] %s' % e.message)
        return False

    def __order_table(self):
        '''
            This function is responsible to get the report details and generate designed report by the columns Domain and IP
        '''
        if REPORT_DETAILS:
            table = PrettyTable(["Domain:", "IP:"])
            for domain in REPORT_DETAILS:
                ip = "\n".join(REPORT_DETAILS[domain])
                table.add_row([domain, ip])
                if len(REPORT_DETAILS[domain]) > 1:
                    table.add_row(['', ''])
            self.logger.info('[Domain Analyzer] Results:\n%s' % table)

    def analyzer_ip(self, ip):
        '''
            This function is responsible to analyzing IP address by following steps:
				1. Recieve of all the host names for this IP
				2. Checks if the hosts results belong to the analyzed domain
				3. appends the details to the `REPORT_DETAILS` variable
        '''
        try:
            domains = filter(None, socket.gethostbyaddr(ip)) # ('edge-star-shv-13-frc1.example.com', ['127.0.0.1'])
            for domain in (self.__resolve_par(d) for d in domains):
                if domain.endswith(self.root_domain):
                    if domain not in REPORT_DETAILS: # Checks if this domain dont added before
                        REPORT_DETAILS[domain].add(ip)
                        POTENTIAL_SUBDOMAINS.add(domain.replace("."+self.root_domain, '')) # Add to potential subdomains
                        self.logger.info("[IP Analyzer] %s exists" % domain)
        except socket.herror:
            pass

    def async_ip_analyzer(self, ip): # Appends IPs to the pool
        self.__ip_pool.imap_unordered(self.analyzer_ip, self.__get_ips(ip))

    def async_domain_analyzer(self):
        '''
            This function is responsible to create the `domain analyzer` pool,
			Additionally, when the domain analyzer finished,
			he calls to the `ip analyzer` pool to run
        '''
        domain_map = self.__domain_pool.map_async(
            self.analyze_domain,
            self.sub_domain_list
        )
        domain_map.join()
        # Wait until ip_pool finish
        self.__ip_pool.join()

    def analyze_domain(self, host):
        '''
            This function is responsible to recieve IP from domain and appends to the report
            if the ip not exists on `OCT_LIST` variable, he append the IP to the `async_ip_analyzer` function
        '''
        try:
            domain = '{host}.{url}'.format(host=host.rstrip('.'), url=self.root_domain) # Create a subdomain to check, example: host=www, url=example.com
            answer = dns.resolver.query(domain, "A") # returns IP from domain
            for data in answer:
                ip = data.address
                REPORT_DETAILS[domain].add(ip)
                oct_ip = self.__oct_builder(ip)
                if self.__is_public(ip) and oct_ip not in OCT_LIST: # Checks if the ip is a public address, and the IP will not exists on the `OCTLIST` variable,
                    self.async_ip_analyzer(ip)
            self.logger.info("[Domain Analyzer] %s exists" % domain)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, Timeout, TypeError):
            pass
        except Exception as e:
            self.logger.exception("[Domain Analyzer][Error] %s" % e.message)

    def data_from_records(self, records):
        '''
            This function is responsible to collect information about the analyzed domain from the DNS Records by the following elements:
			1. IP addresses
			2. Subdomains (MX records and etc.)
        '''
        for domain in set(re.findall('(?:\w+\.)+%s' % re.escape(self.root_domain), records)): # Recieve all the data which contains the analyzed domain
            try:
                address = socket.gethostbyname(domain)
            except socket.gaierror:
                address = 'unknown'
            if domain not in REPORT_DETAILS: # Checks if the subdomain is not exists on `REPORT_DETAILS` list
                REPORT_DETAILS[domain].add(address)
                POTENTIAL_SUBDOMAINS.add(domain.replace(".%s" % self.root_domain, ''))
                self.logger.info("[Domain Analyzer] %s Found on DNS Records" % domain)

        ips = set(re.findall(r'\d+(?:\.\d+){3}', records))
        if ips: # Checks if exists IP addresses on the DNS records
            self.logger.info("[IP Analyzer] Existing IP addresses of the DNS records!")
            for ip in ips:
                if not self.__is_public(ip): # Checks if the IP is private or public
                    self.logger.info("[IP Analyzer] Private IP disclosed: %s" % ip)
                    continue
                oct_ip = self.__oct_builder(ip)
                if oct_ip in OCT_LIST:
                    continue
                OCT_LIST.add(ip)
                self.async_ip_analyzer(ip)

    def dns_data(self, name_server='8.8.8.8', additional_rdclass=65535):
        '''
            This function import all the DNS Records from the domain.
        '''
        self.logger.info("[DNS] Trying to import DNS Records..")
        request = dns.message.make_query(self.root_domain, dns.rdatatype.ANY)
        request.flags |= dns.flags.AD
        request.find_rrset(request.additional, dns.name.root, additional_rdclass,
                           dns.rdatatype.OPT, create=True, force_unique=True)
        response = resolver.dns.query.udp(request, name_server)
        if not response.answer: # If have a DNS records.
            self.logger.error("[DNS][Error] Domain not found.")
            exit(-1)
        records = "\n".join(str(record) for record in response.answer)
        self.logger.info("[DNS] Results:\n%s" % records)
        self.data_from_records(records)

    def main(self, root_domain):
        # TODO: Add local network options
        if re.match(r'^(http://|https://|www\.|(http://|https://)+www\.)', root_domain): # Checks if the domain is clean(without http, https or www)
            self.logger.error("[Domain Analyzer][Error] The domain name must be clean without scheme and sub domain\n"
                              "For example: %s example.com" % path.basename(__file__))
            exit(-1)
        self.root_domain = root_domain
        if not self.zone_transfer(self.logger, self.root_domain):
            self.logger.info("[DNS][Error] Request timed out or transfer not allowed.")
            self.dns_data()
            self.async_domain_analyzer()
            if POTENTIAL_SUBDOMAINS and self.append_sub_domains: # Check if have a subdomains from IP analyzer or DNS records
                self.__add_new_sub_domains()
        self.logger.info('[Domain Analyzer] Finished!')
        if REPORT_DETAILS:
            self.__order_table()

if __name__ == '__main__':
    # Parse The Arguments
    parser = ArgumentParser(description='Domain Analyzer')
    parser.add_argument("domain",
                        help="Domain to analyze")
    parser.add_argument("-o", "--output",
                        default=None,
                        help="Log file")
    parser.add_argument("-t", "--threads",
                        default=50,
                        type=int,
                        help="Number of threads")
    parser.add_argument("-s", "--socket-timeout",
                        default=5,
                        type=int,
                        help="Socket timeout")
    parser.add_argument("-a", "--append-sub-domains",
                        action='store_true',
                        help="Append new sub-domains to sub-domains list")
    parser.add_argument("-l", "--sub-domain-list",
                        default="subdomains.txt",
                        help="Sub domains list")
    sys_args = vars(parser.parse_args())
    domain = sys_args.pop('domain')
    if not path.exists(sys_args['sub_domain_list']):
        parser.error('Sub-domains list not found.')

    domain_analyzer = SubDomainAnalyzer(**sys_args)
    domain_analyzer.main(domain)