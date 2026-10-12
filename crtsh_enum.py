#!/usr/bin/env python3


import argparse
import sys
import requests
import dns.resolver
from termcolor import colored, cprint


def printsubs(subs):
    for sub in subs:
        print(sub)


def query_site(domain):
    cprint(f'[+] Finding subdomains for {domain}', 'green')
    try:
        resp = requests.get(f'https://api.ctlogs.dev/v1/hosts/{domain}', timeout=30)
    except requests.RequestException as e:
        print(f"Error connecting to ctlogs.dev [{e}]")
        sys.exit()

    if resp.status_code != 200:
        print(f"Error connecting to ctlogs.dev [Status: {resp.status_code}]")
        sys.exit()

    try:
        hosts = resp.json().get('hosts') or []
    except ValueError:
        print("Error parsing response from ctlogs.dev")
        sys.exit()

    subs = {}
    for entry in hosts:
        sub = entry.get('host', '').strip().lower()
        if not sub or sub in subs:
            continue
        subs[sub] = 1

    printsubs(subs.keys())

    return subs.keys()


def resolve_dns(domains):
    vuln_domains = []
    for domain in domains:
        # wildcard entries (e.g. *.test.com) can't be resolved directly
        if domain.startswith('*'):
            continue
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

    count = 0
    for domain in vuln_domains:
        try:
            rdata = dns.resolver.resolve(domain, 'CNAME')
            count = count + 1
            for c in rdata:
                print(domain)
                cprint(f'\t{c.target}', 'red')
        except:
            continue

    if count == 0:
        cprint('[!] No vulnerable subdomains found!', 'red')


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
