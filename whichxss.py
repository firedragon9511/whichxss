#!/usr/bin/python3

import sys, argparse, re
from argparse import RawTextHelpFormatter

xss_payloads = None

with open("payloads.txt", "r", encoding="UTF-8") as file:
    xss_payloads = file.read().split("\n")

banner = '''
           _     _      _                  
          | |   (_)    | |                 
 __      _| |__  _  ___| |__ __  _____ ___ 
 \ \ /\ / / '_ \| |/ __| '_  \\ \/ / __/ __|
  \ V  V /| | | | | (__| | | |>  <\__ \__ \\
   \_/\_/ |_| |_|_|\___|_| |_/_/\_\___/___/                                                                               
'''

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=banner, formatter_class=RawTextHelpFormatter, usage="python whichxss.py [option]")

    parser.add_argument('-f',   metavar="WAF_FILTER",   dest="filter",           action='append', default=[], help="A text filtered by WAF")
    parser.add_argument('-fR',  metavar="WAF_REGEX",    dest="filter_regex",    action='append', default=[], help="A text filtered by WAF using Regex")
    parser.add_argument('--show', default=False,        action="store_true",    dest="show_payloads", help="Show results")

    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit()

    if not args.show_payloads:
        print(banner, "\n", "By firedragon9511", "")

    result = xss_payloads

    if len(args.filter_regex) > 0:
        [result.remove(xss) for xss in result.copy() for filter in args.filter_regex if bool(re.search(filter, xss)) and xss in result]

    if len(args.filter) > 0:
        [result.remove(xss) for xss in result.copy() for filter in args.filter if filter in xss and xss in result]

    if args.show_payloads:
        [print(xss) for xss in result]
    
    if not args.show_payloads:
        print("\n", "[INFO] Results: %s, use --show for get results" % str(len(result)))