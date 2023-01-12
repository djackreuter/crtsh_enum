# crtsh_enum

```
usage: crtsh_enum.py [-h] [-u U] [--takeover]

options:
  -h, --help  show this help message and exit
  -u U        domain name of site. e.g., test.com
  --takeover  check if subdomain is vulnerable to a subdomain takeover

```

Pulls unique subdomains for a givin domain from crt.sh. Can also check if any of the subdomains are vulnerable to a subdomain takeover due to a dangling CNAME.
