#!/usr/bin/env python3

import sys, argparse, re, requests, os
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

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=banner, formatter_class=RawTextHelpFormatter, usage="python3 whichxss.py [option]")

    parser.add_argument('-f',     metavar="WAF_FILTER",   dest="filter",          action='append', default=[],   help="A text filtered by WAF")
    parser.add_argument('-fR',    metavar="WAF_REGEX",    dest="filter_regex",    action='append', default=[],   help="A text filtered by WAF using Regex")
    parser.add_argument('-u',     metavar="URL",          dest="url_scan",        action='store',  default=None, help="Heuristic WAF block scan (beta). E.g. -u \"http://siteabc.com/?search=FUZZ\"")
    parser.add_argument('-l',     default=False,          action="store_true",    dest="lower",                  help="Treat all payloads as lowercase in search")
    parser.add_argument('--show', default=False,          action="store_true",    dest="show_payloads",          help="Show results")

    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit()

    if not args.show_payloads:
        print(banner, "\n", "By firedragon9511", "")

    result = xss_payloads

    def process_pseudopayloads(result, combine):
        match_tag   = r"<[a-zA-Z]+>"
        match_event = r"<aaaaaa (on[a-zA-Z]+)=bbbbbb>"
        match_value = r"cccccc=(\".*\")"

        tags   = []
        events = []
        values = []

        for term in result:
            if re.search(match_tag, term):
                tags.append(re.search(match_tag, term).group(0).replace(">", ""))

            if re.search(match_event, term):
                events.append(re.search(match_event, term).group(1))

            if re.search(match_value, term):
                values.append(re.search(match_value, term).group(1))

        if combine:
            elements = ["%s %s=@VALUE@>" % (t, e) for t in tags for e in events]
            [print(e.replace("@VALUE@", v)) for e in elements for v in values]
        else:
            param = "-f \"%s\""
            result = []
            for t in tags:
                result.append(param % (t + "") )
            
            for e in events:
                result.append(param % e)

            for v in values:
                result.append(param % v.replace("\"", "\\\"").replace("bbbbbb", ""))

            cmd = (os.path.basename(sys.executable) + " " + sys.argv[0] + " " + " ".join(result) + " -l --show")
            print(cmd)
            return cmd
            pass

    def heuristic_test(url):
        print()
        with open("heuristic.txt", "r", encoding="UTF-8") as file:
            data = file.read().split("\n")
            data = list(dict.fromkeys(data))
            result = []
            blocked = []
            for term in data:
                u = url.replace("FUZZ", term)
                response = requests.get(u)
                code = response.status_code
                if code == 403:
                    print(bcolors.FAIL + "[HEURISTIC] Blocked by WAF: " + term + bcolors.ENDC)
                    blocked.append(term)
                else:
                    print(bcolors.OKGREEN + "[HEURISTIC] Passed in WAF: " + term + bcolors.ENDC)
                    result.append(term)

            ask1 = input("[ASK] Show filter command results? [Y/n]").lower().strip()
            if ask1 == "y" or ask1 == "":
                cmd = process_pseudopayloads(blocked, False)
                ask3 = input("[ASK] Execute? [Y/n]").lower().strip()
                if ask3 == "y" or ask3 == "":
                    #print(cmd.replace("'", "\\'"))
                    os.system(cmd)

            ask2 = input("[ASK] Show some combinations? [y/N]").lower()
            if ask2 == "y":
                process_pseudopayloads(result, True)


    def pipe(payload):
        if args.lower:
            payload = payload.lower()
        return payload
    
        
    if args.url_scan is not None:
        heuristic_test(args.url_scan)
        sys.exit()

    if len(args.filter_regex) > 0:
        [result.remove(xss) for xss in result.copy() for filter in args.filter_regex if bool(re.search(filter, pipe(xss))) and xss in result]

    if len(args.filter) > 0:
        [result.remove(xss) for xss in result.copy() for filter in args.filter if filter in pipe(xss) and xss in result]

    if args.show_payloads:
        [print(xss) for xss in result]
    
    if not args.show_payloads:
        print("\n", "[INFO] Results: %s, use --show for get results" % str(len(result)))