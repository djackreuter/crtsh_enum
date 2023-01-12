#!/usr/bin/env python3


import argparse
import sys
import requests
import dns.resolver
from termcolor import colored, cprint
from bs4 import BeautifulSoup

def handle_breaks(row):
    addrs = str(row).replace('<td>', '').replace('</td>', '').split('<br/>')
    return addrs

def printsubs(subs):
    for sub in subs:
        print(sub)


def query_site(domain):
    cprint(f'[+] Finding subdomains for {domain}', 'green')
    resp = requests.get(f'https://crt.sh?q={domain}')

    soup = BeautifulSoup(resp.text, 'html.parser')
    trs = soup.find_all('tr')

    subs = {}
    for tr in trs:
        if len(tr.contents) != 15:
            continue

        row = tr.contents[11]
        if row.name == 'th':
            continue


        parsed_subs = []
        if '<br/>' in str(row):
            parsed_subs = handle_breaks(row)

        if len(parsed_subs) != 0:
            for sub in parsed_subs:
                if sub in subs.keys():
                    continue
                else:
                    subs[sub] = 1
            continue


        sub = row.text
        if sub in subs.keys():
            continue
        else:
            subs[sub] = 1

        printsubs(subs.keys())

    return subs.keys()


def resolve_dns(domains):
    vuln_domains = []
    for domain in domains:
        try:
            dns.resolver.resolve(domain)
        except:
            vuln_domains.append(domain)

    return vuln_domains




def check_takeover(domains):
    cprint('[+] Searching domains for potential subdomain takeovers', 'green')
    vuln_domains = resolve_dns(domains)

    if len(vuln_domains) == 0:
        cprint('[!] No vulnerable subdomains found!', 'red')
        return

    for domain in vuln_domains:
        try:
            rdata = dns.resolver.resolve(domain, 'CNAME')
            for c in rdata:
                print(domain)
                cprint(f'\t{c.target}', 'red')
        except:
            continue


if __name__=='__main__':
    parser = argparse.ArgumentParser(prog='crtsh_enum.py')

    parser.add_argument(
        '-u', help='domain name of site. e.g., test.com'
    )
    parser.add_argument(
        '--takeover', help='check if subdomain is vulnerable to a subdomain takeover', action='store_true', default=False
    )


    args = parser.parse_args()
    if args.u == None:
        parser.print_help()
        sys.exit()

    subs = query_site(args.u)
    if args.takeover:
        check_takeover(subs)
